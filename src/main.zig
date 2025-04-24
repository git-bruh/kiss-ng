const std = @import("std");
const config = @import("config.zig");
const types = @import("package.zig");
const dag = @import("dag_zig");

const KISS_COLOR_PRIMARY = "\x1b[1;33m";
const KISS_COLOR_SECONDARY = "\x1b[1;34m";
const KISS_COLOR_CLEAR = "\x1b[m";

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = log,
};

fn toUpper(comptime str: []const u8) [str.len]u8 {
    var out: [str.len]u8 = undefined;

    for (str, 0..) |c, idx| {
        out[idx] = std.ascii.toUpper(c);
    }

    return out;
}

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const log_level = comptime toUpper(level.asText());
    const log_scope = @tagName(scope);

    const fmt_clean = comptime std.fmt.comptimePrint(
        "[{s}] ({s}) ",
        .{ log_level, log_scope },
    ) ++ format ++ "\n";

    const fmt_tty = comptime std.fmt.comptimePrint(
        "{s}[{s}]{s} {s}({s}){s} ",
        .{
            KISS_COLOR_PRIMARY,   log_level, KISS_COLOR_CLEAR,
            KISS_COLOR_SECONDARY, log_scope, KISS_COLOR_CLEAR,
        },
    ) ++ format ++ "\n";

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();

    const stderr = std.io.getStdErr();
    const writer = stderr.writer();

    (if (stderr.supportsAnsiEscapeCodes())
        writer.print(fmt_tty, args)
    else
        writer.print(fmt_clean, args)) catch return;
}

const PkgManager = struct {
    allocator: std.mem.Allocator,
    kiss_config: config.Config,

    const PackageFindError = error{
        PackageNotFound,
    };

    fn find_in_path(self: *PkgManager, pkg_name: []const u8) !std.fs.Dir {
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

    fn construct_dependency_tree(self: *PkgManager, pkg_map: *std.StringHashMap(types.Package), pkg_dag: *dag.DAG([]const u8), pkg_name: ?[]const u8) !void {
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

        for (package.dependencies.items) |dependency| {
            try pkg_dag.add_child(package.name, dependency.name);

            if (pkg_map.contains(dependency.name)) {
                std.log.debug("dependency {s} of {s} already parsed, skipping", .{ dependency.name, package.name });
                continue;
            }

            std.log.debug("looking up dependency {s} of {s}", .{ dependency.name, package.name });
            try self.construct_dependency_tree(pkg_map, pkg_dag, dependency.name);
        }
    }

    pub fn build(self: *PkgManager, pkg_name: ?[]const u8) !void {
        var pkg_map = std.StringHashMap(types.Package).init(self.allocator);
        defer pkg_map.deinit();

        var pkg_dag = dag.DAG([]const u8).init(self.allocator);
        defer pkg_dag.deinit();

        try self.construct_dependency_tree(&pkg_map, &pkg_dag, pkg_name);

        var it = pkg_map.iterator();
        while (it.next()) |entry| {
            std.log.debug("got entry {s}", .{entry.value_ptr.name});
            entry.value_ptr.free();
        }
    }

    pub fn new(allocator: std.mem.Allocator, kiss_config: config.Config) PkgManager {
        return .{ .allocator = allocator, .kiss_config = kiss_config };
    }

    pub fn free(self: *PkgManager) void {
        self.kiss_config.free();
    }
};

pub fn main() !void {
    if (std.os.argv.len < 2) {
        std.log.err("too few arguments provided", .{});
        std.process.exit(1);
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer if (gpa.deinit() == .leak) unreachable;

    var pkg_man = PkgManager.new(allocator, try config.Config.new_from_env(allocator));
    defer pkg_man.free();

    if (std.mem.eql(u8, std.mem.sliceTo(std.os.argv[1], 0), "build")) {
        try pkg_man.build(if (std.os.argv.len > 2) std.mem.sliceTo(std.os.argv[2], 0) else null);
    } else {
        std.log.err("unknown command {s}", .{std.os.argv[1]});
        std.process.exit(1);
    }

    std.log.info(
        "Soon™️",
        .{},
    );
}
