const std = @import("std");
const config = @import("config.zig");
const types = @import("package.zig");
const commands = @import("commands.zig");
const dag = @import("dag_zig");
const git = @import("utils/git.zig");

const PackageFindError = error{
    PackageNotFound,
};

const BuildFilter = enum {
    SkipInstalled,
    SkipInstalledIfSameVersion,
};

pub const PackageManager = struct {
    allocator: std.mem.Allocator,
    kiss_config: config.Config,

    pub fn new(allocator: std.mem.Allocator, kiss_config: config.Config) PackageManager {
        return .{ .allocator = allocator, .kiss_config = kiss_config };
    }

    fn find_in_path(self: *PackageManager, pkg_name: []const u8) !types.Package {
        var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');
        while (it.next()) |path| {
            if (std.mem.eql(u8, path, "")) continue;

            const pkg_path = try std.mem.concat(self.allocator, u8, &.{ path, "/", pkg_name });
            defer self.allocator.free(pkg_path);

            std.log.debug("finding package in path {s}", .{pkg_path});

            var dir = std.fs.openDirAbsolute(pkg_path, .{}) catch |err| {
                std.log.debug("failed to find package at path {s}: {}", .{ pkg_path, err });
                continue;
            };
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
        var package = if (pkg_name != null) try self.find_in_path(pkg_name.?) else try types.Package.new_from_cwd(self.allocator);

        pkg_map.putNoClobber(package.name, package) catch |err| {
            package.free();
            return err;
        };
        try pkg_dag.add_child(package.name, null);

        outer: for (package.dependencies.items) |dependency| {
            const dep_pkg = pkg_map.get(dependency.name) orelse blk: {
                std.log.debug("looking up dependency {s} of {s}", .{ dependency.name, package.name });
                _ = try self.construct_dependency_tree(pkg_map, installed_pkg_map, pkg_dag, filter, dependency.name);
                break :blk pkg_map.get(dependency.name) orelse unreachable;
            };

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
        defer {
            var it = pkg_map.iterator();
            while (it.next()) |entry| entry.value_ptr.free();
            pkg_map.deinit();
        }

        var installed_pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer {
            var it = installed_pkg_map.iterator();
            while (it.next()) |entry| entry.value_ptr.free();
            installed_pkg_map.deinit();
        }

        var pkg_dag = dag.DAG([]const u8).init(self.allocator);
        defer pkg_dag.deinit();

        const root_pkg = "_kiss_ng_root";

        if (pkg_name == null) {
            try pkg_dag.add_child(
                root_pkg,
                try self.construct_dependency_tree(&pkg_map, &installed_pkg_map, &pkg_dag, .SkipInstalled, null),
            );
        } else {
            for (pkg_name.?) |pkg| {
                try pkg_dag.add_child(
                    root_pkg,
                    try self.construct_dependency_tree(&pkg_map, &installed_pkg_map, &pkg_dag, .SkipInstalled, pkg),
                );
            }
        }

        var sorted = std.ArrayList([]const u8).init(self.allocator);
        defer sorted.deinit();

        try pkg_dag.tsort(root_pkg, &sorted);

        for (sorted.items, 0..) |item, idx| {
            std.log.debug("Build Order: {d}, Package: {s}", .{ idx, item });
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

    fn upgrade(self: *PackageManager) !void {
        var installed_dir = try self.kiss_config.get_installed_dir();
        defer installed_dir.close();

        var it = installed_dir.iterate();
        while (try it.next()) |entry| {
            var pkg_dir = try installed_dir.openDir(entry.name, .{});
            var package = try types.Package.new(self.allocator, &pkg_dir);
            defer package.free();

            var repo_pkg = try self.find_in_path(entry.name);
            defer repo_pkg.free();

            if (!std.mem.eql(u8, package.version, repo_pkg.version)) {
                try std.io.getStdOut().writer().print("{s} {s} => {s}\n", .{ package.name, package.version, repo_pkg.version });
            }
        }
    }

    pub fn handle(self: *PackageManager, command: commands.Command) !bool {
        switch (command) {
            .Alternatives => |alt| {
                _ = alt;
            },
            .Build => |build_args| return try self.build(build_args),
            .Checksum => |checksum| {
                if (checksum == null) {
                    var pkg = try types.Package.new_from_cwd(self.allocator);
                    defer pkg.free();

                    return try pkg.download(true);
                }

                for (checksum.?) |package| {
                    var pkg = try self.find_in_path(package);
                    defer pkg.free();

                    if (!try pkg.download(true)) return false;
                }
            },
            .Download => |download| {
                if (download == null) {
                    var pkg = try types.Package.new_from_cwd(self.allocator);
                    defer pkg.free();

                    return try pkg.download(false);
                }

                for (download.?) |package| {
                    var pkg = try self.find_in_path(package);
                    defer pkg.free();

                    if (!try pkg.download(false)) return false;
                }
            },
            .Install => |install| {
                _ = install;
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

                        try std.io.getStdOut().writer().print("{s} {s}\n", .{ package.name, package.version });
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

                        try std.io.getStdOut().writer().print("{s} {s}\n", .{ package.name, package.version });
                    }
                }
            },
            .Preferred => |preferred| {
                _ = preferred;
            },
            .Remove => |remove| {
                _ = remove;
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
                        try std.io.getStdOut().writer().print("{s}/{s}\n", .{ path, package });

                        continue :outer;
                    }

                    std.log.err("{ks} not found", .{package});
                    return false;
                }
            },
            .Update => try self.update(),
            .Upgrade => try self.upgrade(),
            .Version => try std.io.getStdOut().writer().print("{s}\n", .{"0.0.1"}),
        }

        return true;
    }

    pub fn free(self: *PackageManager) void {
        self.kiss_config.free();
    }
};
