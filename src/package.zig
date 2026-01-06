const std = @import("std");
const config = @import("./config.zig");
const checksum = @import("utils/checksum.zig");
const curl_download = @import("utils/download.zig");
const git_util = @import("utils/git.zig");
const archive = @import("utils/archive.zig");
const fs = @import("utils/fs.zig");
const unistd = @cImport(@cInclude("unistd.h"));
const sched = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("sched.h");
});
const mount = @cImport(@cInclude("sys/mount.h"));
const elf = @import("utils/elf.zig");
const sandbox = @import("utils/sandbox.zig");
const signal = @import("utils/signal.zig");

/// A dependency can either be build time (needed just for building the package)
/// or runtime (needed both at build time and runtime)
/// They are read from the newline delimited `depends` file
///
/// cmake make
/// linux-headers make
/// openssl
/// zlib
const Dependency = struct {
    name: []const u8,
    kind: enum { Build, Runtime },
};

/// Source can be fetched via various methods, like from a Git repo, an HTTP url
/// or a local file path. They are read from the newline-delimited `sources` file
///
/// 1. Git (URL + Commit):
///     git+https://sourceware.org/git/glibc.git#1e04dcec491bd8f48b5b74ce3e8414132578a645
///
/// 2. Http (URL, optionally specifying the directory for extraction/relocation):
///     https://ftp.mozilla.org/pub/firefox/releases/119.0/source/firefox-119.0.source.tar.xz
///     https://github.com/jedisct1/libhydrogen/archive/a4de6e098b5bbbd5389eb8058130f782b53826c3.tar.gz libhydrogen
///
/// 3. Local (Relative path on filesystem, optionally specifying directory in build tree):
///     patches/fix-build.patch
///     files/config extras
const Source = union(enum) {
    Git: struct {
        build_path: ?[]const u8,
        clone_url: []const u8,
        commit_hash: ?[]const u8,
    },
    Http: struct {
        build_path: ?[]const u8,
        fetch_url: []const u8,
        checksum: ?[]const u8,
    },
    Local: struct {
        build_path: ?[]const u8,
        path: []const u8,
        checksum: ?[]const u8,
    },
};

/// A package present in a KISS repository is a directory structure providing
/// metadata for building/installing via individual files
///
///  1. build: An executable file (usually shell scripts) to be run in the
///            constructed build environment
///  2. checksums: A list of BLAKE3 checksums corresponding to the sources file
///  3. depends: A list of other dependencies, each of which are parsed into `Dependency`
///  4. sources: A list of sources required for building the package, parsed into `Source`
///  5. version: Version of the package, can be any arbritary string
pub const Package = struct {
    name: []const u8,
    version: []const u8,
    // whether it is needed by another package
    implicit: bool,
    // backing allocated content for sources and dependencies
    backing_contents: [4]?[]const u8,
    dependencies: std.ArrayList(Dependency),
    sources: std.ArrayList(Source),
    dir: std.fs.Dir,
    allocator: std.mem.Allocator,

    pub fn new(allocator: std.mem.Allocator, dir_ptr: *std.fs.Dir) !Package {
        var dir = std.fs.Dir{ .fd = dir_ptr.fd };
        errdefer dir.close();

        var inBuf: [std.fs.max_path_bytes]u8 = undefined;
        var outBuf: [std.fs.max_path_bytes]u8 = undefined;
        const name = std.fs.path.basename(try std.fs.readLinkAbsolute(
            try std.fmt.bufPrint(&inBuf, "/proc/self/fd/{d}", .{dir.fd}),
            &outBuf,
        ));

        const version = try read_until_end(allocator, dir, "version") orelse return error.FileNotFound;
        std.mem.replaceScalar(u8, version, ' ', '-');
        errdefer allocator.free(version);

        const depends = try read_until_end(allocator, dir, "depends");
        errdefer if (depends != null) allocator.free(depends.?);

        const sources = try read_until_end(allocator, dir, "sources");
        errdefer if (sources != null) allocator.free(sources.?);

        const checksums = try read_until_end(allocator, dir, "checksums");
        errdefer if (checksums != null) allocator.free(checksums.?);

        var sourcesArray = try parse_sources(allocator, sliceTillWhitespace(sources orelse ""), sliceTillWhitespace(checksums orelse ""));
        errdefer sourcesArray.deinit(allocator);

        var dependencies = try parse_dependencies(allocator, sliceTillWhitespace(depends orelse ""));
        errdefer dependencies.deinit(allocator);

        return Package{
            .name = try allocator.dupe(u8, name),
            .version = sliceTillWhitespace(version),
            .implicit = false,
            .backing_contents = .{ depends, sources, checksums, version },
            .dependencies = dependencies,
            .sources = sourcesArray,
            .dir = .{ .fd = dir.fd },
            .allocator = allocator,
        };
    }

    pub fn new_from_cwd(allocator: std.mem.Allocator) !Package {
        var dir = try std.fs.cwd().openDir(".", .{});
        return try Package.new(allocator, &dir);
    }

    pub fn new_from_installed_db(allocator: std.mem.Allocator, kiss_config: *const config.Config, name: []const u8) !Package {
        var installed_dir = try kiss_config.get_installed_dir();
        defer installed_dir.close();

        var pkg_dir = try installed_dir.openDir(name, .{});
        return try Package.new(allocator, &pkg_dir);
    }

    // creates a hash map mapping file paths to package names
    // we use an arena to "leak" the backing file buffers and just store
    // pointers to paths in the hash map to avoid repeated allocations
    pub fn get_installed_files_map(arena: *std.heap.ArenaAllocator, kiss_config: *const config.Config) !std.StringHashMap([]const u8) {
        const allocator = arena.allocator();

        var map = std.StringHashMap([]const u8).init(allocator);
        errdefer map.deinit();

        var installed_dir = try kiss_config.get_installed_dir();
        defer installed_dir.close();

        var it = installed_dir.iterate();
        while (try it.next()) |entry| {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const manifest_path = try std.fmt.bufPrint(&buf, "{s}/manifest", .{entry.name});
            const manifest = try installed_dir.openFile(manifest_path, .{});
            defer manifest.close();

            const contents = try manifest.readToEndAlloc(allocator, 1 << 24);
            const entry_copy = try allocator.dupe(u8, entry.name);

            var manifest_iter = std.mem.splitScalar(u8, contents, '\n');
            while (manifest_iter.next()) |path| {
                try map.put(path, entry_copy);
            }
        }

        return map;
    }

    pub fn mark_implicit(self: *Package) void {
        self.implicit = true;
    }

    pub fn version_without_release(self: *const Package) ![]const u8 {
        const idx = std.mem.lastIndexOfScalar(u8, self.version, '-') orelse return error.InvalidArgument;
        return self.version[0..idx];
    }

    pub fn download_and_verify(self: *const Package, generate_checksum: bool) !bool {
        const checksums = if (generate_checksum) try self.dir.createFile("checksums", .{}) else null;
        defer if (checksums) |f| f.close();

        var buf: [128]u8 = undefined;
        var writer = if (checksums) |f| f.writer(&buf) else null;

        for (self.sources.items) |source| switch (source) {
            .Git => |git| {
                var cache_dir = try config.Config.get_source_dir(self.name, git.build_path);
                defer cache_dir.close();

                const dir_name = sliceNameFromUrl(git.clone_url);
                cache_dir.makeDir(dir_name) catch |err| {
                    if (err != error.PathAlreadyExists) return err;
                };
                var git_dir = try cache_dir.openDir(dir_name, .{});
                defer git_dir.close();

                std.log.info("fetching git repo {ks}{ks}{ks}", .{ git.clone_url, "@", git.commit_hash orelse "HEAD" });
                if (!try git_util.initAndPull(self.allocator, git_dir, git.clone_url, git.commit_hash)) {
                    return false;
                }
            },
            .Http => |http| {
                var cache_dir = try config.Config.get_source_dir(self.name, http.build_path);
                defer cache_dir.close();

                const file_name = sliceNameFromUrl(http.fetch_url);
                var file = cache_dir.openFile(file_name, .{}) catch |err| blk: {
                    if (err != error.FileNotFound) return err;

                    var tmp_file_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const tmp_file_name = try std.fmt.bufPrint(&tmp_file_buf, ".{s}", .{file_name});
                    const tmp_file = try cache_dir.createFile(tmp_file_name, .{});
                    defer tmp_file.close();

                    std.log.info("fetching remote file {ks}", .{http.fetch_url});
                    if (!try curl_download.download(self.allocator, tmp_file, http.fetch_url)) {
                        return false;
                    }

                    try cache_dir.rename(tmp_file_name, file_name);
                    break :blk try cache_dir.openFile(file_name, .{});
                };
                defer file.close();
                std.log.info("found remote file {ks}", .{file_name});

                const b3sum = try checksum.b3sum(file);
                if (writer) |*w| {
                    try w.interface.print("{s}\n", .{b3sum});
                    try w.interface.flush();
                } else {
                    if (std.mem.eql(u8, &b3sum, http.checksum orelse {
                        std.log.err("no checksum present for file {ks}", .{file_name});
                        return false;
                    })) {
                        std.log.info("checksum matched {ks} {ks}", .{ b3sum, file_name });
                    } else {
                        std.log.info("checksum mismatch {ks} {ks}", .{ b3sum, file_name });
                        return false;
                    }
                }
            },
            .Local => |local| {
                const file = self.dir.openFile(local.path, .{}) catch |err| {
                    std.log.err("failed to open local file {ks} for checksum generation: {}", .{ local.path, err });
                    return false;
                };
                defer file.close();
                std.log.info("found local file {ks}", .{local.path});

                const b3sum = try checksum.b3sum(file);
                if (writer) |*w| {
                    try w.interface.print("{s}\n", .{b3sum});
                    try w.interface.flush();
                } else {
                    if (std.mem.eql(u8, &b3sum, local.checksum orelse {
                        std.log.err("no checksum present for file {ks}", .{local.path});
                        return false;
                    })) {
                        std.log.info("checksum matched {ks} {ks}", .{ b3sum, local.path });
                    } else {
                        std.log.info("checksum mismatch {ks} {ks}", .{ b3sum, local.path });
                        return false;
                    }
                }
            },
        };

        return true;
    }

    fn get_dependency_file_tree(self: *const Package, arena: *std.heap.ArenaAllocator, kiss_config: *const config.Config, installed_pkg_map: *std.StringHashMap(Package), files_map: *std.StringHashMap(void), name: []const u8) !Package {
        const system_pkg = installed_pkg_map.get(name) orelse blk: {
            const pkg = try Package.new_from_installed_db(self.allocator, kiss_config, name);
            try installed_pkg_map.putNoClobber(name, pkg);
            break :blk pkg;
        };

        const manifest = try read_until_end(arena.allocator(), system_pkg.dir, "manifest");
        if (manifest == null) {
            std.log.err("no manifest found for package {ks}", .{name});
            return error.InvalidArgument;
        }

        var manifest_iter = std.mem.splitScalar(u8, manifest.?, '\n');
        while (manifest_iter.next()) |path| {
            try files_map.put(path, {});
        }

        return system_pkg;
    }

    fn get_dependencies_file_tree(self: *const Package, arena: *std.heap.ArenaAllocator, kiss_config: *const config.Config, visited_packages: *std.StringHashMap(void), installed_pkg_map: *std.StringHashMap(Package), files_map: *std.StringHashMap(void)) !void {
        const is_main_pkg = visited_packages.count() == 0;

        if (is_main_pkg) {
            const base_pkgs: []const []const u8 = &.{ "baselayout", "busybox", "gcc", "git", "gnugrep", "linux-headers", "make", "musl", "pkgconf", "util-linux" };
            for (base_pkgs) |pkg| {
                if (visited_packages.contains(pkg)) continue;
                try visited_packages.put(pkg, {});
                const system_pkg = try self.get_dependency_file_tree(arena, kiss_config, installed_pkg_map, files_map, pkg);
                try system_pkg.get_dependencies_file_tree(arena, kiss_config, visited_packages, installed_pkg_map, files_map);
            }
        }

        for (self.dependencies.items) |dependency| {
            // we don't need to allow access to transitive build-time dependencies
            // as the dependencies are already built & installed
            if ((!is_main_pkg and dependency.kind == .Build) or visited_packages.contains(dependency.name)) continue;
            try visited_packages.put(dependency.name, {});

            const system_pkg = try self.get_dependency_file_tree(arena, kiss_config, installed_pkg_map, files_map, dependency.name);
            try system_pkg.get_dependencies_file_tree(arena, kiss_config, visited_packages, installed_pkg_map, files_map);
        }
    }

    // wraps the actual build function in a thread so that the landlock
    // sandboxing is only limited to the build function and we don't end
    // up restricting the rest of the pgroam
    pub fn build(self: *const Package, kiss_config: *const config.Config, installed_pkg_map: *std.StringHashMap(Package)) !bool {
        signal.block_sigint();
        defer signal.unblock_sigint();

        defer kiss_config.rm_proc_dir() catch |err| std.log.err("failed to clean build directory: {}", .{err});

        var ret: bool = undefined;
        const thread = try std.Thread.spawn(.{}, Package.build_inner, .{ self, kiss_config, installed_pkg_map, &ret });
        thread.join();
        return ret;
    }

    fn build_inner(self: *const Package, kiss_config: *const config.Config, installed_pkg_map: *std.StringHashMap(Package), ret: *bool) !void {
        var landlock = try sandbox.Landlock.init();
        defer landlock.deinit();

        // ensure we can always enumerate directories at any path, but not access files
        try landlock.add_rule_at_path("/", sandbox.Permissions.ReadDir);

        // basic paths
        try landlock.add_rule_at_path(".", sandbox.Permissions.Read);
        try landlock.add_rule_at_path("/proc", sandbox.Permissions.Read | sandbox.Permissions.Write | sandbox.Permissions.Execute);
        try landlock.add_rule_at_path("/dev", sandbox.Permissions.Read | sandbox.Permissions.Write | sandbox.Permissions.Execute);
        try landlock.add_rule_at_path("/tmp", sandbox.Permissions.Read | sandbox.Permissions.Write | sandbox.Permissions.Execute);

        // write access for creating archives
        try landlock.add_rule_at_path(config.CACHE_PATH ++ "/bin", sandbox.Permissions.Write);
        // read access to archives
        try landlock.add_rule_at_path(config.CACHE_PATH ++ "/sources", sandbox.Permissions.Read);
        // write access for logging
        try landlock.add_rule_at_path(config.CACHE_PATH ++ "/logs", sandbox.Permissions.Write);
        // write & execute access for building projects
        try landlock.add_rule_at_path(kiss_config.tmpdir orelse config.CACHE_PATH ++ "/proc", sandbox.Permissions.Read | sandbox.Permissions.Write | sandbox.Permissions.Execute);
        // read & execute access for repository dir (executing build script)
        try landlock.add_rule_with_children(self.dir.fd, sandbox.Permissions.Read | sandbox.Permissions.Execute);

        var sysroot_dir = try kiss_config.get_proc_sysroot_dir();
        defer sysroot_dir.close();

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const sysroot_dir_path = try fs.readLink(sysroot_dir.fd, &buf);

        var inBuf: [std.fs.max_path_bytes]u8 = undefined;
        const build_file_path = try self.copyBuildScript(kiss_config.tmpdir orelse (config.CACHE_PATH ++ "/proc"), &inBuf);

        // allow access to read all files provided by dependencies
        {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            var visited_pkgs_map = std.StringHashMap(void).init(arena.allocator());
            defer visited_pkgs_map.deinit();

            var files_map = std.StringHashMap(void).init(arena.allocator());
            defer files_map.deinit();

            try self.get_dependencies_file_tree(&arena, kiss_config, &visited_pkgs_map, installed_pkg_map, &files_map);

            var files: std.ArrayList([]const u8) = .{};
            defer files.deinit(arena.allocator());

            try files.ensureTotalCapacity(arena.allocator(), files_map.capacity());

            var it = files_map.keyIterator();
            while (it.next()) |path| {
                const fd = std.posix.open(path.*, .{}, 0) catch |err| {
                    std.log.warn("failed to open path {ks} for landlock: {}", .{ path.*, err });
                    continue;
                };
                defer std.posix.close(fd);

                // TODO skip fstat
                try landlock.add_rule(fd, sandbox.Permissions.Read | sandbox.Permissions.Execute);
                files.appendAssumeCapacity(path.*);
            }

            // we need to enumerate installed packages for dependency detection
            var installed_dir = try kiss_config.get_installed_dir();
            defer installed_dir.close();
            try landlock.add_rule_with_children(installed_dir.fd, sandbox.Permissions.Read);

            // sort files in ascending order so directories come before files
            std.mem.sort([]const u8, files.items, {}, struct {
                fn cmp(_: void, lhs: []const u8, rhs: []const u8) bool {
                    return std.mem.order(u8, lhs, rhs) == .lt;
                }
            }.cmp);

            // for some reason we get EXDEV after landlock enforcement
            for (files.items) |path| {
                if (path.len == 0) @panic("got empty path in manifest");
                if (path[path.len - 1] == '/') {
                    sysroot_dir.makeDir(path[1..path.len]) catch |err| {
                        if (err != error.PathAlreadyExists) return err;
                        // this happens in case packages install files to /usr/lib64 instead of /usr/lib
                        // eg. /usr/lib/cmake/ exists in one manifest, but /usr/lib64/cmake/ exists in another
                        std.log.warn("path {ks} already exists (likely due to symlink)", .{path});
                    };
                } else {
                    try std.posix.linkat(-1, path, sysroot_dir.fd, path[1..path.len], 0);
                }
            }

            const unshare_err = std.posix.errno(sched.unshare(sched.CLONE_NEWNS));
            if (unshare_err != .SUCCESS) {
                std.log.err("failed to unshare(): {}", .{unshare_err});
                ret.* = false;
                return;
            }

            const paths: []const []const u8 = &.{ config.CACHE_PATH, config.DB_PATH, "/dev", "/sys", "/proc" };
            for (paths) |dir| {
                var sandbox_buf: [std.fs.max_path_bytes]u8 = undefined;
                const sandbox_dir_path = try std.fmt.bufPrint(&sandbox_buf, "{s}/{s}", .{ sysroot_dir_path, dir });

                var sandbox_dir = try fs.mkdirParents(null, sandbox_dir_path);
                sandbox_dir.close();

                const dir_c = std.posix.toPosixPath(dir) catch unreachable;
                const sandbox_dir_c = std.posix.toPosixPath(sandbox_dir_path) catch unreachable;

                const mount_err = std.posix.errno(mount.mount(
                    &dir_c,
                    &sandbox_dir_c,
                    null,
                    mount.MS_BIND,
                    null,
                ));
                if (mount_err != .SUCCESS) {
                    std.log.err("failed to mount({s}) at {s}: {}", .{ dir, sandbox_dir_path, mount_err });
                    ret.* = false;
                    return;
                }
            }

            try landlock.enforce();
        }

        var build_dir = try kiss_config.get_proc_build_dir();
        defer build_dir.close();

        // must extract sources before unshare() + chroot() as we have to access
        // user-defined directories
        for (self.sources.items) |source| switch (source) {
            .Git => |git| {
                std.log.info("handling git source {ks}", .{git.clone_url});

                var cache_dir = try config.Config.get_source_dir(self.name, git.build_path);
                defer cache_dir.close();

                var sub_build_dir = if (git.build_path) |path| try fs.mkdirParents(build_dir, path) else null;
                defer if (sub_build_dir != null) sub_build_dir.?.close();

                const dir_name = sliceNameFromUrl(git.clone_url);

                var git_dir = try cache_dir.openDir(dir_name, .{ .iterate = true });
                defer git_dir.close();

                try fs.copyDir(git_dir, sub_build_dir orelse build_dir);
            },
            .Http => |http| {
                var cache_dir = try config.Config.get_source_dir(self.name, http.build_path);
                defer cache_dir.close();

                var sub_build_dir = if (http.build_path) |path| try fs.mkdirParents(build_dir, path) else null;
                defer if (sub_build_dir != null) sub_build_dir.?.close();

                const file_name = sliceNameFromUrl(http.fetch_url);
                std.log.info("handling remote source {ks}", .{file_name});

                if (archive.is_extractable(file_name)) {
                    var file = try cache_dir.openFile(file_name, .{});
                    defer file.close();
                    try archive.extract(sub_build_dir orelse build_dir, file, true);
                } else {
                    try cache_dir.copyFile(file_name, sub_build_dir orelse build_dir, file_name, .{});
                }
            },
            .Local => |local| {
                std.log.info("handling local source {ks}", .{local.path});

                var sub_build_dir = if (local.build_path) |path| try fs.mkdirParents(build_dir, path) else null;
                defer if (sub_build_dir != null) sub_build_dir.?.close();

                try self.dir.copyFile(local.path, sub_build_dir orelse build_dir, std.fs.path.basename(local.path), .{});
            },
        };

        const sysroot_dir_path_c = std.posix.toPosixPath(sysroot_dir_path) catch unreachable;
        const chroot_err = std.posix.errno(unistd.chroot(&sysroot_dir_path_c));
        if (chroot_err != .SUCCESS) {
            std.log.err("failed to chroot({s}: {}", .{ sysroot_dir_path, chroot_err });
            ret.* = false;
            return;
        }

        var pkg_dir = try kiss_config.get_proc_pkg_dir();
        defer pkg_dir.close();

        var log_dir = try config.Config.get_log_dir();
        defer log_dir.close();

        var log_file = try config.Config.get_proc_log_file(log_dir, self.name);
        defer log_file.close();

        var chrooted_build_dir = try kiss_config.get_proc_build_dir();
        defer chrooted_build_dir.close();

        // create empty /var/db/kiss/installed in build directory
        {
            var dir = try fs.mkdirParents(pkg_dir, config.DB_PATH_INSTALLED);
            dir.close();
        }

        if (!try self.execBuildScript(chrooted_build_dir, pkg_dir, log_file, build_file_path)) {
            ret.* = false;
            return;
        }

        const no_strip = blk: {
            build_dir.access("nostrip", .{}) catch |err| {
                if (err != error.FileNotFound) return err;
                break :blk !kiss_config.strip;
            };
            break :blk true;
        };

        // only delete log file on successful build
        kiss_config.rm_proc_log_file(log_dir, self.name) catch |err| {
            std.log.err("failed to clean log file: {}", .{err});
        };

        const pkg_db_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ config.DB_PATH_INSTALLED, self.name });

        // re-open here as iteration permission is not guaranteed
        var repo_dir = try self.dir.openDir(".", .{ .iterate = true });
        defer repo_dir.close();
        var installed_db_dir = try fs.mkdirParents(pkg_dir, pkg_db_path);
        defer installed_db_dir.close();
        try fs.copyDir(repo_dir, installed_db_dir);

        var manifest_file = try installed_db_dir.createFile("manifest", .{});
        defer manifest_file.close();

        pkg_dir.access("etc", .{}) catch |err| {
            if (err != error.FileNotFound) return err;
        };

        var etcsums_file = if (pkg_dir.access("etc", .{})) try installed_db_dir.createFile("etcsums", .{}) else |err| blk: {
            if (err == error.FileNotFound) break :blk null;
            return err;
        };
        defer if (etcsums_file != null) etcsums_file.?.close();

        var manifest_buf: [1024]u8 = undefined;
        var manifest_writer = manifest_file.writer(&manifest_buf);
        const manifest = &manifest_writer.interface;
        if (etcsums_file) |file| {
            var etcsums_buf: [128]u8 = undefined;
            var etcsums_writer = file.writer(&etcsums_buf);
            const etcsums = &etcsums_writer.interface;

            try Package.generateManifestEtcsums(pkg_dir, null, manifest, etcsums);
            try etcsums.flush();
        } else {
            try Package.generateManifestEtcsums(pkg_dir, null, manifest, null);
        }
        try manifest.flush();

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        var installed_files_map = try Package.get_installed_files_map(&arena, kiss_config);
        defer installed_files_map.deinit();

        var dependencies = try Package.walk_elf(self.allocator, &installed_files_map, &self.dependencies, pkg_dir, !no_strip);
        defer dependencies.deinit(self.allocator);

        if (dependencies.items.len > 0) {
            const depends = try installed_db_dir.createFile("depends", .{});
            defer depends.close();

            var writer = depends.writer(&buf);
            for (dependencies.items) |dependency| {
                switch (dependency.kind) {
                    .Build => try writer.interface.print("{s} make\n", .{dependency.name}),
                    .Runtime => try writer.interface.print("{s}\n", .{dependency.name}),
                }
            }
            try writer.interface.flush();
        }

        var bin_dir = try config.Config.get_bin_dir();
        defer bin_dir.close();

        const path = try std.fmt.bufPrint(&buf, ".{s}@{s}.tar.zst", .{ self.name, self.version });
        var tmp_file = try bin_dir.createFile(path, .{});
        defer tmp_file.close();

        try archive.compress(pkg_dir, tmp_file);

        bin_dir.deleteFile(path[1..path.len]) catch |err| if (err != error.FileNotFound) return err;
        try bin_dir.rename(path, path[1..path.len]);

        ret.* = true;
    }

    fn copyBuildScript(self: *const Package, tmpdir: []const u8, buf: *[std.fs.max_path_bytes]u8) ![]u8 {
        var outBuf: [std.fs.max_path_bytes]u8 = undefined;

        const repo_path = try fs.readLink(self.dir.fd, buf);
        const build_file_path = try std.fmt.bufPrint(&outBuf, "{s}/build", .{repo_path});
        const tmp_file_path = try std.fmt.bufPrint(buf, "{s}/{d}/script", .{ tmpdir, std.os.linux.getpid() });

        try std.fs.copyFileAbsolute(build_file_path, tmp_file_path, .{});
        return tmp_file_path;
    }

    fn execBuildScript(self: *const Package, build_dir: std.fs.Dir, pkg_dir: std.fs.Dir, log_file: std.fs.File, build_file_path: []const u8) !bool {
        var env_map = try std.process.getEnvMap(self.allocator);
        defer env_map.deinit();

        var outBuf: [std.fs.max_path_bytes]u8 = undefined;
        const build_path = try fs.readLink(build_dir.fd, &outBuf);

        var tmpBuf: [std.fs.max_path_bytes]u8 = undefined;

        // default values for toolchain variables
        if (env_map.get("AR") == null) try env_map.put("AR", "ar");
        if (env_map.get("CC") == null) try env_map.put("CC", "cc");
        if (env_map.get("CXX") == null) try env_map.put("CXX", "c++");
        if (env_map.get("NM") == null) try env_map.put("NM", "nm");
        if (env_map.get("RANLIB") == null) try env_map.put("RANLIB", "ranlib");

        // language-specific flags for sane defaults
        try env_map.put("GOFLAGS", "-trimpath -modcacherw");
        try env_map.put("GOPATH", try std.fmt.bufPrint(&tmpBuf, "{s}/go", .{build_path}));
        try env_map.put("RUSTFLAGS", try std.fmt.bufPrint(&tmpBuf, "--remap-path-prefix={s}=.", .{build_path}));

        const pkg_path = try fs.readLink(pkg_dir.fd, &outBuf);

        var child = std.process.Child.init(&.{ build_file_path, pkg_path, try self.version_without_release() }, self.allocator);

        child.env_map = &env_map;
        child.cwd_dir = build_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        // child processes inherit the sigprocmask so we must temporarily unblock it
        // TODO this has a potential race, we should ideally unblock the signals after
        // fork() but the Child abstraction does not allow us to do so
        signal.unblock_sigint();
        child.spawn() catch |err| {
            signal.block_sigint();
            return err;
        };
        signal.block_sigint();

        var poller = std.io.poll(self.allocator, enum { stdout, stderr }, .{
            .stdout = child.stdout.?,
            .stderr = child.stderr.?,
        });
        defer poller.deinit();

        var stdout_buf: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);

        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);

        var log_buf: [1024]u8 = undefined;
        var log_writer = log_file.writer(&log_buf);

        while (try poller.poll()) {
            try fs.copyToWriters(poller.reader(.stdout), &.{ &stdout_writer.interface, &log_writer.interface });
            try fs.copyToWriters(poller.reader(.stderr), &.{ &stderr_writer.interface, &log_writer.interface });
        }

        try stdout_writer.interface.flush();
        try stderr_writer.interface.flush();

        const term = try child.wait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("build failed with term: {}", .{term});
            return false;
        }

        return true;
    }

    fn generateManifestEtcsums(dir: std.fs.Dir, skip_path_bytes: ?usize, manifest_writer: *std.io.Writer, etcsums_writer: ?*std.Io.Writer) !void {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        var dir_name = try fs.readLink(dir.fd, &buf);
        // skip bytes from the parent directory as we only want paths relative to /
        if (skip_path_bytes) |n| dir_name = dir_name[n..dir_name.len];

        // iterate over all directories first so that we can internally recurse
        // to the leaves, ensuring that we list out all file names before directories
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .directory) {
                var sub_dir = try dir.openDir(entry.name, .{ .iterate = true });
                defer sub_dir.close();
                try Package.generateManifestEtcsums(sub_dir, skip_path_bytes orelse dir_name.len, manifest_writer, etcsums_writer);
            }
        }

        it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) {
                // we must not install libtool / charset.alias files
                if (std.mem.eql(u8, entry.name, "charset.alias") or
                    std.mem.endsWith(u8, entry.name, ".la")) continue;

                // in-case of the root directory skip printing the
                // directory name altogether
                if (skip_path_bytes != null) try manifest_writer.print("{s}/{s}\n", .{ dir_name, entry.name }) else try manifest_writer.print("/{s}\n", .{entry.name});

                if (!std.mem.startsWith(u8, dir_name, "/etc") or etcsums_writer == null) continue;

                // ensure we maintain consistent checksums for symlinks
                var file = if (entry.kind == .file) try dir.openFile(entry.name, .{}) else try std.fs.openFileAbsolute("/dev/null", .{});
                defer file.close();
                const b3sum = try checksum.b3sum(file);
                std.log.info("generated etcsums {ks} for {ks}{ks}{ks}", .{ b3sum, dir_name, "/", entry.name });
                try etcsums_writer.?.print("{s}\n", .{b3sum});
            }
        }

        // ensure we don't include the root directory itself
        if (skip_path_bytes != null) try manifest_writer.print("{s}/\n", .{dir_name});
    }

    fn walk_elf(allocator: std.mem.Allocator, installed_files_map: *const std.StringHashMap([]const u8), source_dependencies: *const std.ArrayList(Dependency), pkg_dir: std.fs.Dir, strip: bool) !std.ArrayList(Dependency) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var elf_iterator = elf.ElfIterator.new(&arena);
        defer elf_iterator.free();

        var dependencies = try source_dependencies.clone(allocator);
        errdefer dependencies.deinit(allocator);

        try elf_iterator.walk(pkg_dir);
        const needed_lib_paths = try elf_iterator.finalize(strip);

        blk: for (needed_lib_paths) |path| {
            // if the file is provided by the package itself then we don't need
            // to check further
            pkg_dir.access(path[1..], .{}) catch |err| {
                if (err != error.FileNotFound) return err;
                const package = installed_files_map.get(path) orelse {
                    std.log.info("need shared library {ks}, not provided by any package", .{path});
                    continue;
                };
                // If the dependency already exists in the list then ensure
                // it is marked as a runtime dependency and not just a build-time one
                for (dependencies.items) |*dependency| {
                    if (std.mem.eql(u8, dependency.name, package)) {
                        if (dependency.kind == .Build) {
                            dependency.kind = .Runtime;
                            std.log.info("need shared library {ks}, provided by {ks}, was marked as build-time dependency", .{ path, package });
                        }

                        continue :blk;
                    }
                }

                // Otherwise, add the dependency to the list
                std.log.info("need shared library {ks}, provided by {ks}", .{ path, package });
                try dependencies.append(allocator, .{
                    .name = package,
                    .kind = .Runtime,
                });

                continue;
            };

            std.log.info("need shared library {ks}, provided by package itself", .{path});
        }

        return dependencies;
    }

    pub fn has_existing_binary(self: *const Package) !bool {
        var bin_dir = try config.Config.get_bin_dir();
        defer bin_dir.close();

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const bin_path = try std.fmt.bufPrint(&buf, "{s}@{s}.tar.zst", .{ self.name, self.version });
        bin_dir.access(bin_path, .{}) catch return false;
        return true;
    }

    pub fn install(self: *const Package, kiss_config: *config.Config) !bool {
        signal.block_sigint();
        defer signal.unblock_sigint();

        const lock_file = try config.Config.acquire_lock();
        defer config.Config.release_lock(lock_file);

        var bin_dir = try config.Config.get_bin_dir();
        defer bin_dir.close();

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const bin_path = try std.fmt.bufPrint(&buf, "{s}@{s}.tar.zst", .{ self.name, self.version });

        var bin_file = try bin_dir.openFile(bin_path, .{});
        defer bin_file.close();

        var extract_dir = try config.Config.get_extract_dir();
        defer {
            extract_dir.close();
            config.Config.rm_extract_dir() catch |err| {
                std.log.warn("failed to delete tree for binary package {ks}: {}", .{ bin_path, err });
            };
        }

        var system_pkg = Package.new_from_installed_db(self.allocator, kiss_config, self.name) catch |err| blk: {
            std.log.warn("did not find existing installed package: {}", .{err});
            break :blk null;
        };
        defer if (system_pkg != null) system_pkg.?.free();
        var system_manifest: ?[]const u8 = null;
        defer if (system_manifest != null) self.allocator.free(system_manifest.?);

        var installed_files_map = std.StringHashMap(void).init(self.allocator);
        defer installed_files_map.deinit();

        if (system_pkg != null) {
            system_manifest = try read_until_end(self.allocator, system_pkg.?.dir, "manifest") orelse {
                std.log.err("no manifest found for installed package {ks}", .{self.name});
                return false;
            };
            var it = std.mem.splitScalar(u8, sliceTillWhitespace(system_manifest.?), '\n');
            while (it.next()) |path| try installed_files_map.putNoClobber(path, {});
        }

        // first extract the binary package as-is and then inspect dependencies
        // and the manifest file to check for missing dependencies and conflicts
        std.log.info("extracting {ks}", .{bin_path});
        try archive.extract(extract_dir, bin_file, false);

        var db_dir = try extract_dir.openDir(config.DB_PATH_INSTALLED, .{});
        defer db_dir.close();

        var pkg_dir = try db_dir.openDir(self.name, .{});
        defer pkg_dir.close();

        var root_dir = try std.fs.openDirAbsolute(kiss_config.root orelse "/", .{});
        defer root_dir.close();

        const depends = try read_until_end(self.allocator, pkg_dir, "depends");
        defer if (depends != null) self.allocator.free(depends.?);

        var dependencies = try parse_dependencies(self.allocator, sliceTillWhitespace(depends orelse ""));
        defer dependencies.deinit(self.allocator);

        if (dependencies.items.len > 0) {
            var installed_pkg_dir = try kiss_config.get_installed_dir();
            defer installed_pkg_dir.close();

            for (dependencies.items) |dependency| {
                if (dependency.kind == .Build) continue;
                installed_pkg_dir.access(dependency.name, .{}) catch |err| {
                    if (err == error.FileNotFound) {
                        std.log.err("dependency {ks} missing", .{dependency.name});
                        if (!kiss_config.force) return false else continue;
                    }
                    return err;
                };
            }
        }

        var manifest = try read_until_end(self.allocator, pkg_dir, "manifest") orelse {
            std.log.err("no manifest found in binary package {ks}", .{bin_path});
            return false;
        };
        defer self.allocator.free(manifest);

        std.log.info("checking for conflicts", .{});

        var regenerate_manifest = false;

        var it = std.mem.splitBackwardsScalar(u8, sliceTillWhitespace(manifest), '\n');
        while (it.next()) |path| {
            if (path.len < 2) {
                std.log.err("path too short {ks}", .{path});
                return false;
            }

            const rel_path = path[1..path.len];

            // we can't conflict with a previous version of ourselves
            if (installed_files_map.contains(path)) continue;

            const system_stat = root_dir.statFile(rel_path) catch |err| {
                if (err == error.FileNotFound) continue;
                std.log.err("failed to stat system path {ks}: {}", .{ path, err });
                return false;
            };
            const stat = try extract_dir.statFile(rel_path);

            const either_dir = system_stat.kind == .directory or stat.kind == .directory;
            const both_dir = system_stat.kind == .directory and stat.kind == .directory;

            if (either_dir) {
                if (!both_dir) {
                    std.log.err("unresolvable conflict at path {ks}, system kind: {}, package kind: {}", .{ path, system_stat.kind, stat.kind });
                    return false;
                }
                // if the directory already exists, ignore it
                continue;
            }

            if (std.mem.startsWith(u8, path, "/etc")) {
                std.log.err("conflicting /etc file at {ks}", .{path});
                return false;
            }

            try fs.ensureDir(extract_dir.makeDir(config.DB_PATH_CHOICES));

            const path_copy = try std.fmt.bufPrint(&buf, "{s}", .{rel_path});
            std.mem.replaceScalar(u8, path_copy, '/', '>');
            var choice_buf: [std.fs.max_path_bytes]u8 = undefined;
            const choice_path = try std.fmt.bufPrint(&choice_buf, "{s}/{s}>{s}", .{ config.DB_PATH_CHOICES, self.name, path_copy });
            std.log.info("path {ks} exists both in system and in package, renaming to {ks}{ks}", .{ path, "/", choice_path });
            try extract_dir.rename(rel_path, choice_path);
            regenerate_manifest = true;
        }

        // re-generate manifest to account for the files we moved around for choices
        if (regenerate_manifest) {
            var manifest_file = try pkg_dir.createFile("manifest", .{});
            defer manifest_file.close();

            var manifest_writer = manifest_file.writer(&buf);
            var writer = &manifest_writer.interface;
            try Package.generateManifestEtcsums(extract_dir, null, writer, null);
            try writer.flush();

            self.allocator.free(manifest);
            manifest = try read_until_end(self.allocator, pkg_dir, "manifest") orelse unreachable;
            it = std.mem.splitBackwardsScalar(u8, sliceTillWhitespace(manifest), '\n');
        }

        if (system_pkg != null) {
            std.log.info("removing system package", .{});
            if (!try system_pkg.?.remove_nolock(kiss_config, true)) return false;
        }

        it.reset();
        try fs.copyStructure(extract_dir, root_dir, &it);

        const post_install_hook = try config.Config.get_hook_path(self.name, "post-install", &buf);
        chrootAndExecHook(kiss_config.root orelse "/", post_install_hook);

        return true;
    }

    // this is a separate function because it is called during the installation
    // process where the lock is already acquired
    pub fn remove_nolock(self: *const Package, kiss_config: *const config.Config, upgrading: bool) !bool {
        var installed_pkg_dir = try kiss_config.get_installed_dir();
        defer installed_pkg_dir.close();

        var deps_it = installed_pkg_dir.iterate();
        // we don't need to check dependent packages if we're upgrading the package
        if (!upgrading) while (try deps_it.next()) |entry| {
            var pkg_dir = try installed_pkg_dir.openDir(entry.name, .{});
            defer pkg_dir.close();

            const depends = try read_until_end(self.allocator, pkg_dir, "depends") orelse continue;
            defer self.allocator.free(depends);

            var dependencies = try parse_dependencies(self.allocator, sliceTillWhitespace(depends));
            defer dependencies.deinit(self.allocator);

            for (dependencies.items) |dependency| {
                if (dependency.kind == .Build) continue;
                if (std.mem.eql(u8, dependency.name, self.name)) {
                    std.log.err("package {ks} is dependent on {ks}", .{ entry.name, self.name });
                    if (!kiss_config.force) return false;
                }
            }
        };

        const manifest = try read_until_end(self.allocator, self.dir, "manifest") orelse @panic("installed pkg has no manifest");
        defer self.allocator.free(manifest);

        var root_dir = try std.fs.openDirAbsolute(kiss_config.root orelse "/", .{});
        defer root_dir.close();

        // we must queue all directory symlinks for later removal and only
        // remove them if the symlink is broken to avoid false removals of
        // symlinks /usr/sbin and /usr/lib64
        var directory_symlinks: std.ArrayList([]const u8) = .{};
        defer directory_symlinks.deinit(self.allocator);

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const pre_remove_hook = try config.Config.get_hook_path(self.name, "pre-remove", &buf);
        chrootAndExecHook(kiss_config.root orelse "/", pre_remove_hook);

        var it = std.mem.splitScalar(u8, manifest, '\n');
        while (it.next()) |path| {
            if (path.len <= 1) continue;

            const is_dir = std.mem.endsWith(u8, path, "/");
            // skip 1 index on path to avoid making it absolute, ensuring
            // it is relative to KISS_ROOT rather than /
            const rel_path = path[1..if (is_dir) path.len - 1 else path.len];

            // checking for directory symlinks only works if we omit the trailing slash
            const stat = try std.posix.fstatat(root_dir.fd, rel_path, std.c.AT.SYMLINK_NOFOLLOW);
            if ((stat.mode & std.c.S.IFMT) == std.c.S.IFLNK) {
                var dir = root_dir.openDir(rel_path, .{}) catch |err| {
                    if (err == error.NotDir or err == error.FileNotFound) {
                        try root_dir.deleteFile(rel_path);
                        continue;
                    }
                    std.log.err("failed to openDir({s}): {}", .{ rel_path, err });
                    return false;
                };
                dir.close();
                // if symlink is a directory, deal with it later
                try directory_symlinks.append(self.allocator, rel_path);
                continue;
            }

            if (is_dir) {
                root_dir.deleteDir(rel_path) catch |err| {
                    // directory can either have more contents or it might've
                    // been deleted as part of the removal process for another
                    // package because there is no exclusivity of directory
                    // ownership
                    if (err == error.DirNotEmpty or err == error.FileNotFound) continue;
                    std.log.err("failed to deleteDir({s}): {}", .{ rel_path, err });
                    return false;
                };
            } else {
                root_dir.deleteFile(rel_path) catch |err| {
                    std.log.err("failed to deleteFile({s}): {}", .{ rel_path, err });
                    return false;
                };
            }
        }

        // only remove broken directory symlinks
        for (directory_symlinks.items) |path| {
            var dir = root_dir.openDir(path, .{}) catch |err| {
                if (err == error.FileNotFound) {
                    try root_dir.deleteFile(path);
                    // try deleting the parent directory as-well if this was
                    // the last file in the directory
                    const parent_dir_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse unreachable;
                    root_dir.deleteDir(path[0..parent_dir_end]) catch |dir_err| {
                        if (dir_err == error.DirNotEmpty) continue;
                        return dir_err;
                    };

                    continue;
                }
                return err;
            };
            dir.close();
        }

        return true;
    }

    pub fn remove(self: *const Package, kiss_config: *const config.Config) !bool {
        const lock_file = try config.Config.acquire_lock();
        defer config.Config.release_lock(lock_file);
        return try self.remove_nolock(kiss_config, false);
    }

    pub fn free(self: *Package) void {
        self.allocator.free(self.name);
        for (self.backing_contents) |bytes| {
            if (bytes != null) self.allocator.free(bytes.?);
        }
        self.dependencies.deinit(self.allocator);
        self.sources.deinit(self.allocator);
        self.dir.close();
    }
};

fn parse_sources(allocator: std.mem.Allocator, sources: []const u8, checksums: []const u8) !std.ArrayList(Source) {
    var sourceIter = std.mem.splitScalar(u8, sources, '\n');
    var checksumIter = std.mem.splitScalar(u8, checksums, '\n');

    var sourceArray: std.ArrayList(Source) = .{};
    errdefer sourceArray.deinit(allocator);

    while (sourceIter.next()) |sourceBuf| {
        var iter = std.mem.splitScalar(u8, sourceBuf, ' ');

        const source = iter.next() orelse unreachable;
        const build_path = iter.next();

        // Ignore empty lines and comments
        if (source.len == 0) {
            continue;
        }

        switch (source[0]) {
            ' ', '#', '\t'...'\r' => continue,
            else => {},
        }

        if (std.mem.startsWith(u8, source, "git+")) {
            var cloneCommitIter = std.mem.splitScalar(u8, source, '#');

            const cloneUrl = cloneCommitIter.next() orelse unreachable;
            const commitHash = cloneCommitIter.next();

            try sourceArray.append(allocator, .{
                .Git = .{ .build_path = build_path, .clone_url = cloneUrl["git+".len..cloneUrl.len], .commit_hash = commitHash },
            });
            continue;
        }

        if (std.mem.containsAtLeast(u8, source, 1, "://")) {
            try sourceArray.append(allocator, .{
                .Http = .{ .build_path = build_path, .fetch_url = source, .checksum = checksumIter.next() },
            });
        } else {
            try sourceArray.append(allocator, .{
                .Local = .{ .build_path = build_path, .path = source, .checksum = checksumIter.next() },
            });
        }
    }

    return sourceArray;
}

fn parse_dependencies(allocator: std.mem.Allocator, depends: []const u8) !std.ArrayList(Dependency) {
    var dependencies: std.ArrayList(Dependency) = .{};

    var iter = std.mem.splitScalar(u8, depends, '\n');
    while (iter.next()) |dependency| {
        if (std.mem.eql(u8, dependency, "")) continue;
        var nameMakeIter = std.mem.tokenizeAny(u8, dependency, &.{ ' ', '\t' });
        const name = nameMakeIter.next() orelse unreachable;
        try dependencies.append(allocator, Dependency{
            .name = name,
            .kind = if (nameMakeIter.next() == null) .Runtime else .Build,
        });
    }

    return dependencies;
}

fn read_until_end(allocator: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) !?[]u8 {
    const file = dir.openFile(name, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();

    return try file.readToEndAlloc(allocator, 1 << 24);
}

fn sliceTillWhitespace(contents: []const u8) []const u8 {
    // strip trailig whitespace
    var len = contents.len;
    while (len > 0) : (len -= 1) {
        if (!std.ascii.isWhitespace(contents[len - 1])) {
            return contents[0..len];
        }
    }
    return contents;
}

fn sliceNameFromUrl(url: []const u8) []const u8 {
    return url[(std.mem.lastIndexOfScalar(u8, url, '/') orelse unreachable) + 1 .. url.len];
}

fn chrootAndExecHook(root: []const u8, path: []const u8) void {
    const pid = std.c.fork();
    const pid_err = std.posix.errno(pid);
    if (pid_err != .SUCCESS) {
        std.log.err("failed to fork(): {}", .{pid_err});
        @panic("fork() failed");
    }

    if (pid == 0) {
        const c_root = std.posix.toPosixPath(root) catch @panic("path too long");
        const chroot_err = std.posix.errno(unistd.chroot(&c_root));
        if (chroot_err != .SUCCESS) {
            std.log.err("failed to chroot({s}): {}", .{ root, chroot_err });
            std.process.exit(1);
        }

        const c_path = std.posix.toPosixPath(path) catch @panic("path too long");
        std.log.err("failed to execve({s}): {}", .{ path, std.posix.execveZ(&c_path, &.{ &c_path, null }, std.c.environ) });
        std.process.exit(1);
    } else {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(-1, &status, 0);
        status = (status & 0xff00) >> 8;

        if (status == 0) {
            std.log.info("successfully executed hook at {ks} in {ks}", .{ path, root });
        } else {
            std.log.warn("failed to execute hook at {ks} in {ks}: {d}, continuing", .{ path, root, status });
        }
    }
}
