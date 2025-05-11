const std = @import("std");
const config = @import("./config.zig");
const checksum = @import("utils/checksum.zig");
const curl_download = @import("utils/download.zig");
const git_util = @import("utils/git.zig");
const archive = @import("utils/archive.zig");
const fs = @import("utils/fs.zig");
const unistd = @cImport(@cInclude("unistd.h"));

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

    pub fn new(allocator: std.mem.Allocator, dir: *std.fs.Dir) !Package {
        errdefer dir.close();

        var inBuf: [std.fs.max_path_bytes]u8 = @splat(0);
        var outBuf: [std.fs.max_path_bytes]u8 = @splat(0);
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

        const sourcesArray = try parse_sources(allocator, sliceTillWhitespace(sources orelse ""), sliceTillWhitespace(checksums orelse ""));
        errdefer sourcesArray.deinit();

        const dependencies = try parse_dependencies(allocator, sliceTillWhitespace(depends orelse ""));
        errdefer dependencies.deinit();

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
                if (checksums) |f| {
                    try f.writer().print("{s}\n", .{b3sum});
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
                if (checksums) |f| {
                    try f.writer().print("{s}\n", .{b3sum});
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

    pub fn build(self: *const Package, kiss_config: *const config.Config) !bool {
        var build_dir = try kiss_config.get_proc_build_dir();
        defer {
            build_dir.close();
            kiss_config.rm_proc_dir() catch |err| {
                std.log.err("failed to clean build directory: {}", .{err});
            };
        }

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
                    try archive.extract(sub_build_dir orelse build_dir, file);
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

        var pkg_dir = try kiss_config.get_proc_pkg_dir();
        defer pkg_dir.close();

        var log_dir = try config.Config.get_log_dir();
        defer log_dir.close();

        var log_file = try config.Config.get_proc_log_file(log_dir, self.name);
        defer log_file.close();

        if (!try self.execBuildScript(build_dir, pkg_dir, log_file)) return false;

        // only delete log file on successful build
        kiss_config.rm_proc_log_file(log_dir, self.name) catch |err| {
            std.log.err("failed to clean log file: {}", .{err});
        };

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const pkg_db_path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ config.DB_PATH_INSTALLED, self.name });

        // re-open here as iteration permission is not guaranteed
        var repo_dir = try self.dir.openDir(".", .{ .iterate = true });
        defer repo_dir.close();
        var installed_db_dir = try fs.mkdirParents(pkg_dir, pkg_db_path);
        defer installed_db_dir.close();
        try fs.copyDir(repo_dir, installed_db_dir);

        // try self.strip(nostrip);
        // try self.fix_deps();
        var manifest_file = try installed_db_dir.createFile("manifest", .{});
        defer manifest_file.close();

        if (pkg_dir.access("etc", .{}) != error.FileNotFound) {}

        var etcsums_file = if (pkg_dir.access("etc", .{})) try installed_db_dir.createFile("etcsums", .{}) else |err| blk: {
            if (err == error.FileNotFound) break :blk null;
            return err;
        };
        defer if (etcsums_file != null) etcsums_file.?.close();
        try Package.generateManifestEtcsums(pkg_dir, null, manifest_file.writer(), if (etcsums_file != null) etcsums_file.?.writer() else null);

        var bin_dir = try config.Config.get_bin_dir();
        defer bin_dir.close();

        const path = try std.fmt.bufPrint(&buf, ".{s}@{s}.tar.zst", .{ self.name, self.version });
        var tmp_file = try bin_dir.createFile(path, .{});
        defer tmp_file.close();

        try archive.compress(pkg_dir, tmp_file);

        bin_dir.deleteFile(path[1..path.len]) catch |err| if (err != error.FileNotFound) return err;
        try bin_dir.rename(path, path[1..path.len]);

        return true;
    }

    fn execBuildScript(self: *const Package, build_dir: std.fs.Dir, pkg_dir: std.fs.Dir, log_file: std.fs.File) !bool {
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

        const repo_path = try fs.readLink(self.dir.fd, &outBuf);
        const build_file_path = try std.fmt.bufPrint(&tmpBuf, "{s}/build", .{repo_path});
        const pkg_path = try fs.readLink(pkg_dir.fd, &outBuf);

        var child = std.process.Child.init(&.{ build_file_path, pkg_path, try self.version_without_release() }, self.allocator);

        child.env_map = &env_map;
        child.cwd_dir = build_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        var poller = std.io.poll(self.allocator, enum { stdout, stderr }, .{
            .stdout = child.stdout.?,
            .stderr = child.stderr.?,
        });
        defer poller.deinit();

        var stdoutWriter = std.io.getStdOut().writer();
        var stderrWriter = std.io.getStdErr().writer();
        var logWriter = log_file.writer();

        while (try poller.poll()) {
            try fs.copyFifo(poller.fifo(.stdout), &.{ &stdoutWriter, &logWriter });
            try fs.copyFifo(poller.fifo(.stderr), &.{ &stderrWriter, &logWriter });
        }

        const term = try child.wait();
        if (term != .Exited) {
            @panic("process didn't terminate as expected");
        }

        if (term.Exited != 0) {
            std.log.err("build failed with status {d}", .{term.Exited});
            return false;
        }

        return true;
    }

    fn generateManifestEtcsums(dir: std.fs.Dir, skip_path_bytes: ?usize, manifest_writer: std.fs.File.Writer, etcsums_writer: ?std.fs.File.Writer) !void {
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

                try manifest_writer.print("{s}/{s}\n", .{ dir_name, entry.name });

                if (!std.mem.startsWith(u8, dir_name, "/etc")) continue;

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

    pub fn install(self: *const Package) !void {
        // TODO lock
        // verify manifest
        // verify dependencies installed
        // run post-install hook

        _ = self;
    }

    pub fn remove(self: *const Package, kiss_config: *const config.Config) !void {
        var sys_dir = try kiss_config.get_installed_dir();
        defer sys_dir.close();

        var pkg_dir = try sys_dir.openDir(self.name, .{});
        defer pkg_dir.close();

        const manifest = try read_until_end(self.allocator, &pkg_dir, "manifest") orelse @panic("installed pkg has no manifest");
        defer self.allocator.free(manifest);

        var root_dir = try std.fs.openDirAbsolute(kiss_config.root orelse "/", .{});
        defer root_dir.close();

        // we must queue all directory symlinks for later removal and only
        // remove them if the symlink is broken to avoid false removals of
        // symlinks /usr/sbin and /usr/lib64
        var directory_symlinks = std.ArrayList([]const u8).init(self.allocator);
        defer directory_symlinks.deinit();

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const pre_remove_hook = try config.Config.get_hook_path(self.name, "pre-remove", &buf);
        chrootAndExecHook(kiss_config.root orelse "/", pre_remove_hook);

        var it = std.mem.splitScalar(u8, manifest, '\n');
        while (it.next()) |path| {
            if (path.len <= 1) continue;

            // skip 1 index on path to avoid making it absolute, ensuring
            // it is relative to KISS_ROOT rather than /
            const rel_path = path[1..path.len];

            if (std.mem.endsWith(u8, path, "/")) {
                root_dir.deleteDir(rel_path) catch |err| {
                    if (err == error.DirNotEmpty) continue;
                    return err;
                };
            } else {
                const stat = try root_dir.statFile(rel_path);
                if (stat.kind == .sym_link) {
                    var dir = root_dir.openDir(rel_path, .{}) catch |err| {
                        if (err == error.NotDir) {
                            try root_dir.deleteFile(rel_path);
                            continue;
                        }
                        return err;
                    };
                    dir.close();
                    // if symlink is a directory, deal with it later
                    try directory_symlinks.append(rel_path);
                    continue;
                }
                try root_dir.deleteFile(rel_path);
            }
        }

        for (directory_symlinks.items) |path| {
            var dir = root_dir.openDir(path, .{}) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            dir.close();
            try root_dir.deleteFile(path);
        }
    }

    pub fn free(self: *Package) void {
        self.allocator.free(self.name);
        for (self.backing_contents) |bytes| {
            if (bytes != null) self.allocator.free(bytes.?);
        }
        self.dependencies.deinit();
        self.sources.deinit();
        self.dir.close();
    }
};

fn parse_sources(allocator: std.mem.Allocator, sources: []const u8, checksums: []const u8) !std.ArrayList(Source) {
    var sourceIter = std.mem.splitScalar(u8, sources, '\n');
    var checksumIter = std.mem.splitScalar(u8, checksums, '\n');

    var sourceArray = std.ArrayList(Source).init(allocator);
    errdefer sourceArray.deinit();

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

            try sourceArray.append(.{
                .Git = .{ .build_path = build_path, .clone_url = cloneUrl["git+".len..cloneUrl.len], .commit_hash = commitHash },
            });
            continue;
        }

        if (std.mem.containsAtLeast(u8, source, 1, "://")) {
            try sourceArray.append(.{
                .Http = .{ .build_path = build_path, .fetch_url = source, .checksum = checksumIter.next() },
            });
        } else {
            try sourceArray.append(.{
                .Local = .{ .build_path = build_path, .path = source, .checksum = checksumIter.next() },
            });
        }
    }

    return sourceArray;
}

fn parse_dependencies(allocator: std.mem.Allocator, depends: []const u8) !std.ArrayList(Dependency) {
    var dependencies = std.ArrayList(Dependency).init(allocator);

    var iter = std.mem.splitScalar(u8, depends, '\n');
    while (iter.next()) |dependency| {
        var nameMakeIter = std.mem.splitScalar(u8, dependency, ' ');
        const name = nameMakeIter.next() orelse unreachable;
        if (std.mem.eql(u8, name, "")) continue;
        try dependencies.append(Dependency{
            .name = name,
            .kind = if (nameMakeIter.next() == null) .Runtime else .Build,
        });
    }

    return dependencies;
}

fn read_until_end(allocator: std.mem.Allocator, dir: *std.fs.Dir, name: []const u8) !?[]u8 {
    const file = dir.openFile(name, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();

    return try file.readToEndAlloc(allocator, 1 << 16);
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
        std.log.err("failed to execve({s}): {}", .{ path, std.posix.execveZ(&c_path, undefined, undefined) });
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
