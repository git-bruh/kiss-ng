const std = @import("std");
const config = @import("config.zig");
const types = @import("package.zig");
const commands = @import("commands.zig");
const dag = @import("dag_zig");
const git = @import("utils/git.zig");

const PackageFindError = error{
    PackageNotFound,
};

pub const PackageManager = struct {
    allocator: std.mem.Allocator,
    kiss_config: config.Config,

    pub fn new(allocator: std.mem.Allocator, kiss_config: config.Config) PackageManager {
        return .{ .allocator = allocator, .kiss_config = kiss_config };
    }

    fn find_in_path(self: *PackageManager, pkg_name: []const u8) !std.fs.Dir {
        var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');
        while (it.next()) |path| {
            if (std.mem.eql(u8, path, "")) continue;

            const pkg_path = try std.mem.concat(self.allocator, u8, &.{ path, "/", pkg_name });
            defer self.allocator.free(pkg_path);

            std.log.debug("finding package in path {s}", .{pkg_path});

            const dir = std.fs.openDirAbsolute(pkg_path, .{ .access_sub_paths = true, .iterate = true }) catch |err| {
                std.log.debug("failed to find package at path {s}: {}", .{ pkg_path, err });
                continue;
            };
            return dir;
        }

        std.log.debug("package {s} not found in any path", .{pkg_name});
        return PackageFindError.PackageNotFound;
    }

    fn construct_dependency_tree(self: *PackageManager, pkg_map: *std.StringHashMap(types.Package), pkg_dag: *dag.DAG([]const u8), pkg_name: ?[]const u8) ![]const u8 {
        var dir = if (pkg_name != null) try self.find_in_path(pkg_name.?) else try std.fs.cwd().openDir(".", .{ .access_sub_paths = true, .iterate = true });

        var package = try types.Package.new(self.allocator, &dir);
        errdefer package.free();

        try pkg_map.putNoClobber(package.name, package);
        try pkg_dag.add_child(package.name, null);

        for (package.dependencies.items) |dependency| {
            try pkg_dag.add_child(package.name, dependency.name);

            if (pkg_map.contains(dependency.name)) {
                std.log.debug("dependency {s} of {s} already parsed, skipping", .{ dependency.name, package.name });
                continue;
            }

            std.log.debug("looking up dependency {s} of {s}", .{ dependency.name, package.name });
            _ = try self.construct_dependency_tree(pkg_map, pkg_dag, dependency.name);
        }

        return package.name;
    }

    fn build(self: *PackageManager, pkg_name: ?[]const u8) !void {
        var pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer {
            var it = pkg_map.iterator();
            while (it.next()) |entry| entry.value_ptr.free();
            pkg_map.deinit();
        }

        var pkg_dag = dag.DAG([]const u8).init(self.allocator);
        defer pkg_dag.deinit();

        const root_pkg = try self.construct_dependency_tree(&pkg_map, &pkg_dag, pkg_name);

        var sorted = std.ArrayList([]const u8).init(self.allocator);
        defer sorted.deinit();

        try pkg_dag.tsort(root_pkg, &sorted);

        for (sorted.items, 0..) |item, idx| {
            std.log.debug("Build Order: {d}, Package: {s}", .{ idx, item });
        }
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
        try std.posix.chdir(self.kiss_config.root orelse "/");
        try std.posix.chdir(config.DB_PATH_INSTALLED);

        var dir = try std.fs.cwd().openDir(".", .{ .iterate = true });
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            var pkg_dir = try std.fs.cwd().openDir(entry.name, .{});
            var package = try types.Package.new(self.allocator, &pkg_dir);
            defer package.free();

            var repo_pkg_dir = try self.find_in_path(entry.name);
            var repo_pkg = try types.Package.new(self.allocator, &repo_pkg_dir);
            defer repo_pkg.free();

            if (!std.mem.eql(u8, package.version, repo_pkg.version)) {
                try std.io.getStdOut().writer().print("{s} {s} => {s}\n", .{ package.name, package.version, repo_pkg.version });
            }
        }
    }

    pub fn handle(self: *PackageManager, command: commands.Command) !void {
        switch (command) {
            .Alternatives => |alt| {
                _ = alt;
            },
            .Build => |build_args| {
                _ = build_args;
            },
            .Checksum => |checksum| {
                for (checksum.?) |package| {
                    var dir = try self.find_in_path(package);
                    var pkg = try types.Package.new(self.allocator, &dir);
                    defer pkg.free();

                    _ = try pkg.checksum_verify();
                }
            },
            .Download => |download| {
                for (download.?) |package| {
                    var dir = try self.find_in_path(package);
                    var pkg = try types.Package.new(self.allocator, &dir);
                    defer pkg.free();

                    _ = try pkg.download(false);
                }
            },
            .Install => |install| {
                _ = install;
            },
            .List => |list| {
                try std.posix.chdir(self.kiss_config.root orelse "/");
                try std.posix.chdir(config.DB_PATH_INSTALLED);

                var dir = try std.fs.cwd().openDir(".", .{ .iterate = true });
                defer dir.close();

                if (list == null) {
                    var it = dir.iterate();
                    while (try it.next()) |entry| {
                        var pkg_dir = try std.fs.cwd().openDir(entry.name, .{});
                        var package = try types.Package.new(self.allocator, &pkg_dir);
                        defer package.free();

                        try std.io.getStdOut().writer().print("{s} {s}\n", .{ package.name, package.version });
                    }
                } else {
                    for (list.?) |pkg_name| {
                        var pkg_dir = std.fs.cwd().openDir(pkg_name, .{}) catch |err| {
                            if (err == error.FileNotFound) {
                                std.log.err("{ks} not found", .{pkg_name});
                                continue;
                            }
                            return err;
                        };
                        var package = try types.Package.new(self.allocator, &pkg_dir);
                        defer package.free();

                        try std.io.getStdOut().writer().print("{s} {s}", .{ package.name, package.version });
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
                if (search == null) return;
                for (search.?) |package| {
                    var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');
                    while (it.next()) |path| {
                        if (std.mem.eql(u8, path, "")) continue;
                        std.posix.chdir(path) catch |err| {
                            std.log.debug("failed to chdir for search to {s}: {}", .{ path, err });
                            continue;
                        };

                        std.posix.access(package, std.posix.F_OK) catch continue;
                        try std.io.getStdOut().writer().print("{s}/{s}\n", .{ path, package });
                    }
                }
            },
            .Update => try self.update(),
            .Upgrade => try self.upgrade(),
            .Version => try std.io.getStdOut().writer().print("{s}\n", .{"0.0.1"}),
        }
    }

    pub fn free(self: *PackageManager) void {
        self.kiss_config.free();
    }
};
