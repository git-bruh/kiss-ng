const std = @import("std");
const config = @import("config.zig");
const types = @import("package.zig");
const commands = @import("commands.zig");
const dag = @import("dag_zig");

pub const PackageManager = struct {
    allocator: std.mem.Allocator,
    kiss_config: config.Config,

    const PackageFindError = error{
        PackageNotFound,
    };

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
        errdefer dir.close();

        var inBuf: [std.fs.max_path_bytes]u8 = @splat(0);
        var outBuf: [std.fs.max_path_bytes]u8 = @splat(0);
        const pkg_basename = std.fs.path.basename(try std.fs.readLinkAbsolute(
            try std.fmt.bufPrint(&inBuf, "/proc/self/fd/{d}", .{dir.fd}),
            &outBuf,
        ));

        var package = try types.Package.new(self.allocator, dir, pkg_basename);
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

    pub fn handle(self: *PackageManager, command: commands.Command) !void {
        switch (command) {
            .Alternatives => |alt| {
                _ = alt;
            },
            .Build => |build_args| {
                _ = build_args;
            },
            .Checksum => |checksum| {
                _ = checksum;
            },
            .Download => |download| {
                _ = download;
            },
            .Install => |install| {
                _ = install;
            },
            .List => |list| {
                _ = list;
            },
            .Preferred => |preferred| {
                _ = preferred;
            },
            .Remove => |remove| {
                _ = remove;
            },
            .Search => |search| {
                _ = search;
            },
            .Update => try self.update(),
            .Upgrade => {},
            .Version => {
                std.log.info("{s}", .{"0.0.1"});
            },
        }
    }

    fn update(self: *PackageManager) !void {
        var visited_map = std.BufMap.init(self.allocator);
        defer visited_map.deinit();

        std.log.info("Updating repositories", .{});

        var it = std.mem.splitScalar(u8, self.kiss_config.path, ':');

        while (it.next()) |path| {
            if (std.mem.eql(u8, path, "")) continue;

            std.posix.chdir(path) catch |err| {
                std.log.err("failed to enter path {ks}: {}", .{ path, err });
                continue;
            };

            const revParseArgs: []const []const u8 = &.{ "git", "rev-parse", "--show-toplevel" };
            var revParseC = std.process.Child.init(revParseArgs, self.allocator);

            revParseC.stdout_behavior = .Pipe;
            revParseC.stderr_behavior = .Pipe;

            try revParseC.spawn();

            const buf_size = 1024;

            var repo_path = try std.ArrayListUnmanaged(u8).initCapacity(self.allocator, buf_size);
            defer repo_path.deinit(self.allocator);

            var stderr = try std.ArrayListUnmanaged(u8).initCapacity(self.allocator, buf_size);
            defer stderr.deinit(self.allocator);

            try revParseC.collectOutput(self.allocator, &repo_path, &stderr, buf_size);

            _ = repo_path.orderedRemove(repo_path.items.len - 1);

            var term = try revParseC.wait();
            if (term == .Exited) {
                if (term.Exited != 0) {
                    std.log.info("not a git repo: {ks}, continuing", .{path});
                    continue;
                }
            } else {
                @panic("process didn't terminate as expected");
            }

            if (visited_map.get(repo_path.items) != null) continue;
            try visited_map.put(repo_path.items, "");

            std.log.info("updating repo at {ks}", .{repo_path.items});

            const pullArgs: []const []const u8 = &.{ "git", "pull" };
            var pullC = std.process.Child.init(pullArgs, self.allocator);
            term = try pullC.spawnAndWait();
            if (term == .Exited and term.Exited != 0) {
                std.log.err("failed to update repo {ks}: code {d}", .{ repo_path.items, term.Exited });
                return;
            }
        }

        std.log.info("Run 'kiss U' to upgrade packages", .{});
    }

    pub fn new(allocator: std.mem.Allocator, kiss_config: config.Config) PackageManager {
        return .{ .allocator = allocator, .kiss_config = kiss_config };
    }

    pub fn free(self: *PackageManager) void {
        self.kiss_config.free();
    }
};
