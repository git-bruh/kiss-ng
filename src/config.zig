const std = @import("std");

pub const DB_PATH = "var/db/kiss";
pub const DB_PATH_INSTALLED = DB_PATH ++ "/installed";

pub const CACHE_PATH = "/var/cache/kiss";

pub const Config = struct {
    allocator: std.mem.Allocator,

    /// KISS_PATH
    /// path for searching KISS packages
    path: []const u8,
    /// KISS_ROOT
    /// path for installing KISS packages
    root: ?[]const u8,
    /// KISS_TMPDIR
    /// base directory for temporary build trees
    tmpdir: ?[]const u8,

    /// KISS_DEBUG
    /// whether to preserve build directory for debugging
    debug: bool,
    /// KISS_STRIP
    /// whether to strip symbols before packaging
    strip: bool,

    pub fn new_from_env(allocator: std.mem.Allocator) !Config {
        const root = std.process.getEnvVarOwned(allocator, "KISS_ROOT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (root != null) allocator.free(root.?);

        const path = try std.fmt.allocPrint(allocator, "{s}:{s}{s}", .{
            std.posix.getenv("KISS_PATH") orelse "",
            root orelse "/",
            DB_PATH_INSTALLED,
        });
        errdefer allocator.free(path);

        const tmpdir = std.process.getEnvVarOwned(allocator, "KISS_TMPDIR") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (tmpdir != null) allocator.free(tmpdir.?);

        const debug = std.posix.getenv("KISS_DEBUG");
        const strip = std.posix.getenv("KISS_STRIP");

        return Config{
            .allocator = allocator,
            .path = path,
            .root = root,
            .tmpdir = tmpdir,
            // defaults to false
            .debug = (debug != null and debug.?[0] == '1'),
            // defaults to true
            .strip = !(strip != null and strip.?[0] == '0'),
        };
    }

    pub fn get_source_dir(pkg_name: []const u8, build_path: ?[]const u8) !std.fs.Dir {
        try ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/sources"));
        var cache_dir = try std.fs.openDirAbsolute(CACHE_PATH ++ "/sources", .{});
        defer cache_dir.close();

        try ensureDir(cache_dir.makeDir(pkg_name));

        const pkg_dir = try cache_dir.openDir(pkg_name, .{});
        if (build_path == null) return pkg_dir;

        var prev_dir = pkg_dir;

        var it = std.mem.splitScalar(u8, build_path.?, '/');
        while (it.next()) |path| {
            errdefer prev_dir.close();
            try ensureDir(prev_dir.makeDir(path));
            const new_dir = try prev_dir.openDir(path, .{});
            prev_dir.close();
            prev_dir = new_dir;
        }

        return prev_dir;
    }

    pub fn get_bin_dir() !std.fs.Dir {
        try ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/bin"));
        return try std.fs.openDirAbsolute(CACHE_PATH ++ "/bin", .{});
    }

    pub fn get_logs_dir() !std.fs.Dir {
        const epoch = std.time.epoch.EpochSeconds{
            .secs = @intCast(std.time.timestamp()),
        };
        const epoch_day = epoch.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        const buf: ["YYYY-MM-DD".len]u8 = undefined;
        try std.fmt.bufPrint(&buf, "{d}-{d:02}-{d:02}", .{ year_day.year, month_day.month.numeric(), month_day.day_index });

        try ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/logs"));
        const cache_dir = try std.fs.openDirAbsolute(CACHE_PATH ++ "/logs", .{});
        defer cache_dir.close();

        try ensureDir(cache_dir.makeDir(buf));
        return try cache_dir.openDir(buf, .{});
    }

    pub fn get_installed_dir(self: *const Config) !std.fs.Dir {
        var root_dir = try std.fs.openDirAbsolute(self.root orelse "/", .{});
        defer root_dir.close();

        return try root_dir.openDir(DB_PATH_INSTALLED, .{ .iterate = true });
    }

    pub fn free(self: *Config) void {
        self.allocator.free(self.path);
        if (self.root != null) self.allocator.free(self.root.?);
    }
};

fn ensureDir(err: anytype) !void {
    if (err == error.PathAlreadyExists) return;
    return err;
}
