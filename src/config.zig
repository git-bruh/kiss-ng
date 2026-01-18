const std = @import("std");
const fs = @import("utils/fs.zig");

pub const DB_PATH = "/var/db/kiss";
pub const DB_PATH_INSTALLED = DB_PATH[1..DB_PATH.len] ++ "/installed";
pub const DB_PATH_CHOICES = DB_PATH[1..DB_PATH.len] ++ "/choices";

pub const CACHE_PATH = "/var/cache/kiss";

pub const Config = struct {
    allocator: std.mem.Allocator,

    /// KISS_PATH
    /// path for searching KISS packages
    path: []const u8,
    /// KISS_SANDBOX_FILES
    /// files to bind mount to the sandbox (eg. for ccache/distcc/icecream)
    files: ?[]const u8,
    sandbox_files: std.ArrayList([]const u8),
    /// KISS_ROOT
    /// path for installing KISS packages
    root: ?[]const u8,

    /// KISS_DEBUG
    /// whether to preserve build directory for debugging
    debug: bool,
    /// KISS_STRIP
    /// whether to strip symbols before packaging
    strip: bool,
    /// KISS_PROMPT
    /// whether to prompt for upgrades/implicit dependencies
    prompt: bool,
    /// KISS_KEEPLOG
    /// whether to preserve log files for successful builds
    keeplog: bool,
    /// KISS_FORCE
    /// whether to force operations like installation/removal by skipping
    /// dependency checks
    force: bool,

    pub fn new_from_env(allocator: std.mem.Allocator) !Config {
        const root = std.process.getEnvVarOwned(allocator, "KISS_ROOT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (root != null) allocator.free(root.?);

        const path = try std.fmt.allocPrint(allocator, "{s}:{s}/{s}", .{
            std.posix.getenv("KISS_PATH") orelse "",
            root orelse "/",
            DB_PATH_INSTALLED,
        });
        errdefer allocator.free(path);

        var sandbox_files: std.ArrayList([]const u8) = .{};
        errdefer sandbox_files.deinit(allocator);

        try sandbox_files.appendSlice(allocator, &.{ CACHE_PATH, DB_PATH, "/dev", "/sys", "/proc" });
        const files = std.process.getEnvVarOwned(allocator, "KISS_SANDBOX_FILES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (files != null) allocator.free(files.?);
        var it = std.mem.splitScalar(u8, files orelse "", ' ');
        while (it.next()) |file| if (file.len > 0) try sandbox_files.append(allocator, file);

        const debug = std.posix.getenv("KISS_DEBUG");
        const strip = std.posix.getenv("KISS_STRIP");
        const prompt = std.posix.getenv("KISS_PROMPT");
        const keeplog = std.posix.getenv("KISS_KEEPLOG");
        const force = std.posix.getenv("KISS_FORCE");

        return Config{
            .allocator = allocator,
            .path = path,
            .files = files,
            .sandbox_files = sandbox_files,
            .root = root,
            // defaults to false
            .debug = (debug != null and debug.?[0] == '1'),
            // defaults to true
            .strip = !(strip != null and strip.?[0] == '0'),
            // defaults to true
            .prompt = !(prompt != null and prompt.?[0] == '0'),
            // defaults to false
            .keeplog = (keeplog != null and keeplog.?[0] == '1'),
            // defaults to false
            .force = (force != null and force.?[0] == '1'),
        };
    }

    pub fn get_source_dir(pkg_name: []const u8, build_path: ?[]const u8) !std.fs.Dir {
        try fs.ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/sources"));
        var cache_dir = try std.fs.openDirAbsolute(CACHE_PATH ++ "/sources", .{});
        defer cache_dir.close();

        try fs.ensureDir(cache_dir.makeDir(pkg_name));

        var pkg_dir = try cache_dir.openDir(pkg_name, .{});
        if (build_path == null) return pkg_dir;
        defer pkg_dir.close(); // will be duplicated in mkdirParents
        return try fs.mkdirParents(pkg_dir, build_path.?);
    }

    pub fn get_bin_dir() !std.fs.Dir {
        try fs.ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/bin"));
        return try std.fs.openDirAbsolute(CACHE_PATH ++ "/bin", .{});
    }

    // must be used with flock
    pub fn get_extract_dir() !std.fs.Dir {
        try fs.ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/extract"));
        return try std.fs.openDirAbsolute(CACHE_PATH ++ "/extract", .{ .iterate = true });
    }

    pub fn rm_extract_dir() !void {
        return try std.fs.deleteTreeAbsolute(CACHE_PATH ++ "/extract");
    }

    pub fn get_log_dir() !std.fs.Dir {
        const epoch = std.time.epoch.EpochSeconds{
            .secs = @intCast(std.time.timestamp()),
        };
        const epoch_day = epoch.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        var buf: ["YYYY-MM-DD".len]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{d}-{d:02}-{d:02}", .{ year_day.year, month_day.month.numeric(), month_day.day_index });

        try fs.ensureDir(std.fs.makeDirAbsolute(CACHE_PATH ++ "/logs"));
        var cache_dir = try std.fs.openDirAbsolute(CACHE_PATH ++ "/logs", .{});
        defer cache_dir.close();

        try fs.ensureDir(cache_dir.makeDir(path));
        return try cache_dir.openDir(path, .{});
    }

    pub fn get_proc_log_file(log_dir: std.fs.Dir, pkg_name: []const u8) !std.fs.File {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}-{d}", .{ pkg_name, std.os.linux.getpid() });
        return try log_dir.createFile(path, .{});
    }

    pub fn rm_proc_log_file(self: *const Config, log_dir: std.fs.Dir, pkg_name: []const u8) !void {
        if (!self.debug and !self.keeplog) {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "{s}-{d}", .{ pkg_name, std.os.linux.getpid() });
            return try log_dir.deleteFile(path);
        }
    }

    pub fn get_proc_build_dir() !std.fs.Dir {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/{d}/build", .{ CACHE_PATH ++ "/proc", std.os.linux.getpid() });

        return try fs.mkdirParents(null, path);
    }

    pub fn get_proc_pkg_dir() !std.fs.Dir {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/{d}/pkg", .{ CACHE_PATH ++ "/proc", std.os.linux.getpid() });

        return try fs.mkdirParents(null, path);
    }

    pub fn get_proc_sysroot_dir() !std.fs.Dir {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/{d}/sysroot", .{ CACHE_PATH ++ "/proc", std.os.linux.getpid() });

        return try fs.mkdirParents(null, path);
    }

    // cleans build & package directories
    pub fn rm_proc_dir(self: *const Config) !void {
        if (!self.debug) {
            var dir = try std.fs.openDirAbsolute(CACHE_PATH ++ "/proc", .{});
            defer dir.close();

            var buf: [std.fs.max_path_bytes]u8 = undefined;
            try dir.deleteTree(try std.fmt.bufPrint(&buf, "{d}", .{std.os.linux.getpid()}));
        }
    }

    pub fn get_installed_dir(self: *const Config) !std.fs.Dir {
        var root_dir = try std.fs.openDirAbsolute(self.root orelse "/", .{});
        defer root_dir.close();

        return try root_dir.openDir(DB_PATH_INSTALLED, .{ .iterate = true });
    }

    pub fn get_hook_path(pkg_name: []const u8, hook_name: []const u8, out: *[std.fs.max_path_bytes]u8) ![]const u8 {
        return std.fmt.bufPrint(out, "/{s}/{s}/{s}", .{ DB_PATH_INSTALLED, pkg_name, hook_name });
    }

    // returns whether the lock was alreadty acquired
    // in the same process
    pub fn acquire_lock() !std.fs.File {
        const path = CACHE_PATH ++ "/lock";
        std.log.info("acquiring lock file at {ks}...", .{path});
        const lock_file = try std.fs.createFileAbsolute(path, .{ .lock = .exclusive });
        std.log.info("acquired lock file", .{});
        return lock_file;
    }

    pub fn release_lock(file: std.fs.File) void {
        file.unlock();
    }

    pub fn free(self: *Config) void {
        self.allocator.free(self.path);
        self.sandbox_files.deinit(self.allocator);
        if (self.root != null) self.allocator.free(self.root.?);
        if (self.files != null) self.allocator.free(self.files.?);
    }
};
