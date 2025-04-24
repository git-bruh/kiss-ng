const std = @import("std");

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

    /// cache directory for logs, sources, binaries
    cache: []const u8,

    /// KISS_DEBUG
    /// whether to preserve build directory for debugging
    debug: bool,
    /// KISS_STRIP
    /// whether to strip symbols before packaging
    strip: bool,

    pub fn new_from_env(allocator: std.mem.Allocator) !Config {
        const path = try std.process.getEnvVarOwned(allocator, "KISS_PATH");
        errdefer allocator.free(path);

        const root = std.process.getEnvVarOwned(allocator, "KISS_ROOT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (root != null) allocator.free(root.?);

        const tmpdir = std.process.getEnvVarOwned(allocator, "KISS_TMPDIR") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (tmpdir != null) allocator.free(tmpdir.?);

        const cache = try get_cache_directory(allocator);
        errdefer allocator.free(cache);

        const debug = std.posix.getenv("KISS_DEBUG");
        const strip = std.posix.getenv("KISS_STRIP");

        return Config{
            .allocator = allocator,
            .path = path,
            .root = root,
            .tmpdir = tmpdir,
            .cache = cache,
            // defaults to false
            .debug = (debug != null and debug.?[0] == '1'),
            // defaults to true
            .strip = !(strip != null and strip.?[0] == '0'),
        };
    }

    pub fn free(self: *Config) void {
        self.allocator.free(self.path);
        if (self.root != null) self.allocator.free(self.root.?);
        self.allocator.free(self.cache);
    }
};

fn get_cache_directory(allocator: std.mem.Allocator) ![]u8 {
    const xdg_cache_home = std.posix.getenv("XDG_CACHE_HOME");
    if (xdg_cache_home != null) return std.fmt.allocPrint(allocator, "{s}/kiss", .{xdg_cache_home.?});

    const home = std.posix.getenv("HOME") orelse return error.EnvironmentVariableNotFound;
    return std.fmt.allocPrint(allocator, "{s}/.cache/kiss", .{home});
}
