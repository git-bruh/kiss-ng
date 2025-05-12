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
        const new_dir = try prev_dir.openDir(sub_path, .{ .iterate = true });
        prev_dir.close();
        prev_dir = new_dir;
    }
    return prev_dir;
}

pub fn copyDir(src_dir: std.fs.Dir, target_dir: std.fs.Dir) !void {
    var it = src_dir.iterate();
    while (try it.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                var src = try src_dir.openDir(entry.name, .{ .iterate = true });
                defer src.close();

                try target_dir.makeDir(entry.name);

                var target = try target_dir.openDir(entry.name, .{ .iterate = true });
                defer target.close();

                try copyDir(src, target);
            },
            .sym_link => {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const link = try src_dir.readLink(entry.name, &buf);
                try target_dir.symLink(entry.name, link, .{});
            },
            .file => try src_dir.copyFile(entry.name, target_dir, entry.name, .{}),
            else => {
                std.log.err("unsupported file {ks} of kind {}", .{ entry.name, entry.kind });
                return error.InvalidArgument;
            },
        }
    }
}

// paths is an iterator which lists directories first and then the sub-paths
pub fn copyStructure(src_dir: std.fs.Dir, target_dir: std.fs.Dir, paths: anytype) !void {
    while (paths.next()) |path| {
        // the caller must verify that the path entries are valid
        const rel_path = path[1..path.len];

        // ignore directory if it exists in the system, otherwise create one
        // with the same permissions
        if (std.mem.endsWith(u8, rel_path, "/")) {
            target_dir.access(rel_path, .{}) catch |err| {
                if (err != error.FileNotFound) {
                    std.log.err("failed to access system path {ks}: {}", .{ path, err });
                    return err;
                }

                const stat = try src_dir.statFile(rel_path);
                try std.posix.mkdirat(target_dir.fd, rel_path, stat.mode);
            };
            continue;
        }

        // try renaming the file if we are on the same filesystem
        // otherwise do a normal copy
        std.fs.rename(src_dir, rel_path, target_dir, rel_path) catch |err| {
            if (err != error.RenameAcrossMountPoints) {
                return err;
            }

            const stat = try src_dir.statFile(rel_path);
            if (stat.kind == .sym_link) {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_path = try src_dir.readLink(rel_path, &buf);
                try target_dir.symLink(link_path, rel_path, .{});
                continue;
            }

            try src_dir.copyFile(rel_path, target_dir, rel_path, .{});
        };
    }
}

pub fn readLink(fd: std.c.fd_t, outBuf: *[std.fs.max_path_bytes]u8) ![]const u8 {
    var inBuf: [std.fs.max_path_bytes]u8 = undefined;
    return try std.fs.readLinkAbsolute(
        try std.fmt.bufPrint(&inBuf, "/proc/self/fd/{d}", .{fd}),
        outBuf,
    );
}

pub fn copyFifo(fifo: *std.io.PollFifo, writers: []const *std.fs.File.Writer) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = fifo.read(&buf);
        if (n == 0) break;

        for (writers) |writer| try writer.writeAll(buf[0..n]);
    }
}
