const std = @import("std");

pub fn ensureDir(err: anytype) !void {
    if (err == error.PathAlreadyExists) return;
    return err;
}

pub fn mkdirParents(dir: ?std.fs.Dir, path: []const u8) !std.fs.Dir {
    // must duplicate the original FD to avoid invalidating the original object
    var prev_dir = if (dir != null) std.fs.Dir{ .fd = try std.posix.dup(dir.?.fd) } else try std.fs.openDirAbsolute("/", .{});
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |sub_path| {
        if (std.mem.eql(u8, sub_path, "")) continue;
        errdefer prev_dir.close();
        try ensureDir(prev_dir.makeDir(sub_path));
        const new_dir = try prev_dir.openDir(sub_path, .{});
        prev_dir.close();
        prev_dir = new_dir;
    }
    return prev_dir;
}
