const std = @import("std");
const config = @import("config.zig");
const types = @import("package.zig");
const commands = @import("commands.zig");
const dag = @import("dag_zig");
const git = @import("utils/git.zig");
const fs = @import("utils/fs.zig");

const PackageFindError = error{
    PackageNotFound,
};

const BuildFilter = enum {
    SkipInstalled,
    SkipInstalledIfSameVersion,
};

const ROOT_PKG = "_kiss_ng_root";

pub const PackageManager = struct {
    allocator: std.mem.Allocator,
    kiss_config: config.Config,

    pub fn new(allocator: std.mem.Allocator, kiss_config: config.Config) PackageManager {
        return .{ .allocator = allocator, .kiss_config = kiss_config };
    }

    fn prompt(self: *PackageManager) !void {
        if (!self.kiss_config.prompt) return;
        try std.fs.File.stdout().writeAll("Continue? Press Enter to continue or Ctrl+C to abort");
        var buffer: [1]u8 = undefined;
        _ = try std.fs.File.stdout().readAll(&buffer);
    }

    fn find_in_path(self: *PackageManager, pkg_name: []const u8) !types.Package {
        var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');
        while (it.next()) |path| {
            if (std.mem.eql(u8, path, "")) continue;
            var repo_dir = try std.fs.openDirAbsolute(path, .{});
            defer repo_dir.close();
            var dir = repo_dir.openDir(pkg_name, .{}) catch continue;
            return try types.Package.new(self.allocator, &dir);
        }

        std.log.debug("package {s} not found in any path", .{pkg_name});
        return PackageFindError.PackageNotFound;
    }

    fn construct_dependency_tree(
        self: *PackageManager,
        pkg_map: *std.StringHashMap(types.Package),
        installed_pkg_map: *std.StringHashMap(types.Package),
        pkg_dag: *dag.DAG([]const u8),
        filter: BuildFilter,
        pkg_name: ?[]const u8,
    ) ![]const u8 {
        const package = if (pkg_name != null) pkg_map.get(pkg_name.?) orelse blk: {
            var pkg = try self.find_in_path(pkg_name.?);
            pkg_map.putNoClobber(pkg.name, pkg) catch |err| {
                pkg.free();
                return err;
            };
            break :blk pkg;
        } else blk: {
            var pkg = try types.Package.new_from_cwd(self.allocator);
            pkg_map.putNoClobber(pkg.name, pkg) catch |err| {
                pkg.free();
                return err;
            };
            break :blk pkg;
        };

        try pkg_dag.add_child(package.name, null);

        outer: for (package.dependencies.items) |dependency| {
            var dep_pkg = pkg_map.getPtr(dependency.name) orelse blk: {
                std.log.debug("looking up dependency {ks} of {ks}", .{ dependency.name, package.name });
                _ = try self.construct_dependency_tree(pkg_map, installed_pkg_map, pkg_dag, filter, dependency.name);
                break :blk pkg_map.getPtr(dependency.name) orelse unreachable;
            };
            // mark the package as implicit so we can ensure to install the
            // package before building the package that needs it
            dep_pkg.mark_implicit();

            const installed_dep_pkg = installed_pkg_map.get(dependency.name) orelse blk: {
                var installed_dir = try self.kiss_config.get_installed_dir();
                defer installed_dir.close();

                var pkg_dir = installed_dir.openDir(dependency.name, .{}) catch break :blk null;
                const installed_pkg = try types.Package.new(self.allocator, &pkg_dir);
                try installed_pkg_map.putNoClobber(dependency.name, installed_pkg);
                break :blk installed_pkg;
            };

            if (installed_dep_pkg != null) {
                switch (filter) {
                    .SkipInstalled => continue :outer,
                    .SkipInstalledIfSameVersion => if (std.mem.eql(u8, dep_pkg.version, installed_dep_pkg.?.version)) continue :outer,
                }
            }

            try pkg_dag.add_child(package.name, dependency.name);
        }

        return package.name;
    }

    fn build(self: *PackageManager, pkg_name: ?[][]const u8) !bool {
        var pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer clear_pkg_map(&pkg_map);

        var installed_pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer clear_pkg_map(&installed_pkg_map);

        var pkg_dag = dag.DAG([]const u8).init(self.allocator);
        defer pkg_dag.deinit();

        if (pkg_name == null) {
            try pkg_dag.add_child(
                ROOT_PKG,
                try self.construct_dependency_tree(&pkg_map, &installed_pkg_map, &pkg_dag, .SkipInstalled, null),
            );
        } else {
            for (pkg_name.?) |pkg| {
                try pkg_dag.add_child(
                    ROOT_PKG,
                    try self.construct_dependency_tree(&pkg_map, &installed_pkg_map, &pkg_dag, .SkipInstalled, pkg),
                );
            }
        }

        var sorted: std.ArrayList([]const u8) = .{};
        defer sorted.deinit(self.allocator);

        try pkg_dag.tsort(ROOT_PKG, &sorted);

        if (sorted.items.len == 0) return true;

        var requires_implicit_packages = false;
        for (sorted.items[0 .. sorted.items.len - 1], 0..) |item, idx| {
            const pkg = pkg_map.get(item) orelse unreachable;
            if (pkg.implicit) {
                requires_implicit_packages = true;
                std.log.info("({d}/{d}) will build package (implicit) {ks}", .{ idx + 1, sorted.items.len - 1, pkg.name });
            } else {
                std.log.info("({d}/{d}) will build package (explicit) {ks}", .{ idx + 1, sorted.items.len - 1, pkg.name });
            }
            if (!try pkg.download_and_verify(false)) return false;
        }
        if (requires_implicit_packages) try self.prompt();

        for (sorted.items[0 .. sorted.items.len - 1], 0..) |item, idx| {
            const pkg = pkg_map.get(item) orelse unreachable;
            std.log.info("({d}/{d}) building package {ks}", .{ idx + 1, sorted.items.len - 1, pkg.name });

            if (!try pkg.build(&self.kiss_config, &installed_pkg_map)) return false;

            std.log.info("successfully built {ks}", .{pkg.name});
            if (pkg.implicit) {
                std.log.info("{ks} needed as dependency, installing", .{pkg.name});
                if (!try pkg.install(&self.kiss_config)) return false;

                // must remove entry as the existing FDs are now invalid
                var installed_pkg = installed_pkg_map.get(pkg.name) orelse continue;
                _ = installed_pkg_map.remove(pkg.name);
                installed_pkg.free();
            }
        }

        return true;
    }

    fn upgrade(self: *PackageManager) !bool {
        var installed_dir = try self.kiss_config.get_installed_dir();
        defer installed_dir.close();

        var pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer clear_pkg_map(&pkg_map);

        var installed_pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer clear_pkg_map(&installed_pkg_map);

        var candidates: std.ArrayList([]const u8) = .{};
        defer candidates.deinit(self.allocator);

        var it = installed_dir.iterate();
        while (try it.next()) |entry| {
            var pkg_dir = try installed_dir.openDir(entry.name, .{});
            var package = try types.Package.new(self.allocator, &pkg_dir);
            installed_pkg_map.putNoClobber(package.name, package) catch |err| {
                package.free();
                return err;
            };

            var repo_pkg = try self.find_in_path(entry.name);
            pkg_map.putNoClobber(repo_pkg.name, repo_pkg) catch |err| {
                repo_pkg.free();
                return err;
            };

            if (!std.mem.eql(u8, package.version, repo_pkg.version)) {
                try candidates.append(self.allocator, package.name);
                std.log.info("{ks} {s} => {s}", .{ package.name, package.version, repo_pkg.version });
            }
        }

        if (candidates.items.len == 0) return true;
        try self.prompt();

        var pkg_dag = dag.DAG([]const u8).init(self.allocator);
        defer pkg_dag.deinit();

        for (candidates.items) |pkg| {
            try pkg_dag.add_child(ROOT_PKG, try self.construct_dependency_tree(&pkg_map, &installed_pkg_map, &pkg_dag, .SkipInstalledIfSameVersion, pkg));
        }

        var sorted: std.ArrayList([]const u8) = .{};
        defer sorted.deinit(self.allocator);

        try pkg_dag.tsort(ROOT_PKG, &sorted);

        if (sorted.items.len == 0) return true;

        // must verify from the sorted array here because pkg_map contains all packages
        for (sorted.items[0 .. sorted.items.len - 1]) |pkg_name| if (!try (pkg_map.get(pkg_name) orelse unreachable).download_and_verify(false)) return false;

        for (sorted.items[0 .. sorted.items.len - 1], 0..) |item, idx| {
            const pkg = pkg_map.get(item) orelse unreachable;

            if (try pkg.has_existing_binary()) {
                std.log.info("({d}/{d}) installing existing binary for package {ks}", .{ idx + 1, sorted.items.len - 1, pkg.name });
                if (!try pkg.install(&self.kiss_config)) return false;
                continue;
            }

            std.log.info("({d}/{d}) building package {ks}", .{ idx + 1, sorted.items.len - 1, pkg.name });

            if (!try pkg.build(&self.kiss_config, &installed_pkg_map)) return false;
            if (!try pkg.install(&self.kiss_config)) return false;

            // must remove entry as the existing FDs are now invalid
            var installed_pkg = installed_pkg_map.get(pkg.name) orelse continue;
            _ = installed_pkg_map.remove(pkg.name);
            installed_pkg.free();
        }

        return true;
    }

    fn update(self: *PackageManager) !void {
        var visited_map = std.BufMap.init(self.allocator);
        defer visited_map.deinit();

        std.log.info("Updating repositories", .{});

        var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');

        while (it.next()) |path| {
            if (std.mem.eql(u8, path, "")) continue;

            const git_dir = try std.fs.openDirAbsolute(path, .{});
            var root = try git.repoRoot(self.allocator, git_dir) orelse {
                std.log.info("not a git repo {ks}", .{path});
                continue;
            };
            defer root.deinit(self.allocator);

            // trailing newline
            _ = root.orderedRemove(root.items.len - 1);

            if (visited_map.get(root.items) != null) continue;
            try visited_map.put(root.items, "");

            std.log.info("updating repo at {ks}", .{root.items});
            if (!try git.pull(self.allocator, git_dir)) {
                std.log.err("failed to update repo {ks}", .{root.items});
                continue;
            }
        }

        std.log.info("Run {ks} to upgrade packages", .{"kiss U"});
    }

    pub fn handle(self: *PackageManager, command: commands.Command) !bool {
        var stdout_buffer: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        switch (command) {
            .Alternatives => |alt| {
                _ = alt;
            },
            .Build => |build_args| return try self.build(build_args),
            .Checksum => |checksum| {
                if (checksum == null) {
                    var pkg = try types.Package.new_from_cwd(self.allocator);
                    defer pkg.free();

                    return try pkg.download_and_verify(true);
                }

                for (checksum.?) |package| {
                    var pkg = try self.find_in_path(package);
                    defer pkg.free();

                    if (!try pkg.download_and_verify(true)) return false;
                }
            },
            .Download => |download| {
                if (download == null) {
                    var pkg = try types.Package.new_from_cwd(self.allocator);
                    defer pkg.free();

                    return try pkg.download_and_verify(false);
                }

                for (download.?) |package| {
                    var pkg = try self.find_in_path(package);
                    defer pkg.free();

                    if (!try pkg.download_and_verify(false)) return false;
                }
            },
            .Install => |install| {
                if (install == null) {
                    var pkg = try types.Package.new_from_cwd(self.allocator);
                    defer pkg.free();

                    return try pkg.install(&self.kiss_config);
                }

                for (install.?) |package| {
                    var pkg = try self.find_in_path(package);
                    defer pkg.free();

                    if (!try pkg.install(&self.kiss_config)) return false;
                }
            },
            .List => |list| {
                var installed_dir = try self.kiss_config.get_installed_dir();
                defer installed_dir.close();

                if (list == null) {
                    var it = installed_dir.iterate();
                    while (try it.next()) |entry| {
                        var pkg_dir = try installed_dir.openDir(entry.name, .{});
                        var package = try types.Package.new(self.allocator, &pkg_dir);
                        defer package.free();

                        try stdout.print("{s} {s}\n", .{ package.name, package.version });
                    }
                } else {
                    for (list.?) |pkg_name| {
                        var pkg_dir = installed_dir.openDir(pkg_name, .{}) catch |err| {
                            if (err == error.FileNotFound) {
                                std.log.err("{ks} not found", .{pkg_name});
                                continue;
                            }
                            return err;
                        };
                        var package = try types.Package.new(self.allocator, &pkg_dir);
                        defer package.free();

                        try stdout.print("{s} {s}\n", .{ package.name, package.version });
                    }
                }
            },
            .Preferred => |preferred| {
                _ = preferred;
            },
            .Remove => |remove| {
                if (remove == null) {
                    var buf: [std.fs.max_path_bytes]u8 = undefined;
                    const name = std.fs.path.basename(try fs.readLink(std.fs.cwd().fd, &buf));
                    var pkg = try types.Package.new_from_installed_db(self.allocator, &self.kiss_config, name);
                    defer pkg.free();
                    return try pkg.remove(&self.kiss_config);
                }

                for (remove.?) |name| {
                    var package = try types.Package.new_from_installed_db(self.allocator, &self.kiss_config, name);
                    defer package.free();
                    if (!try package.remove(&self.kiss_config)) return false;
                }
            },
            .Search => |search| {
                if (search == null) return true;
                outer: for (search.?) |package| {
                    var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');
                    while (it.next()) |path| {
                        if (std.mem.eql(u8, path, "")) continue;
                        std.posix.chdir(path) catch |err| {
                            std.log.debug("failed to chdir for search to {s}: {}", .{ path, err });
                            continue;
                        };

                        std.posix.access(package, std.posix.F_OK) catch continue;
                        try stdout.print("{s}/{s}\n", .{ path, package });

                        continue :outer;
                    }

                    std.log.err("{ks} not found", .{package});
                    return false;
                }
            },
            .Update => try self.update(),
            .Upgrade => return try self.upgrade(),
            .Version => try stdout.print("{s}\n", .{"0.0.1"}),
        }

        try stdout.flush();

        return true;
    }

    pub fn free(self: *PackageManager) void {
        self.kiss_config.free();
    }
};

fn clear_pkg_map(map: *std.StringHashMap(types.Package)) void {
    var it = map.iterator();
    while (it.next()) |entry| entry.value_ptr.free();
    map.deinit();
}
