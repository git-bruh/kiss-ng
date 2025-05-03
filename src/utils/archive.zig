const std = @import("std");
const libarchive = @cImport({
    @cInclude("archive.h");
    @cInclude("archive_entry.h");
});

const ArchiveError = error{
    Eof,
    Retry,
    Fatal,
};

// returns whether to retry
fn check(res: c_int) !void {
    const err = libarchive.archive_error_string(libarchive.archive_errno());

    switch (res) {
        libarchive.ARCHIVE_OK => return,
        libarchive.ARCHIVE_RETRY => return ArchiveError.Retry,
        libarchive.ARCHIVE_EOF => return ArchiveError.Eof,
        libarchive.ARCHIVE_WARN => std.log.warn("libarchive returned warning: {s}", .{err}),
        else => {
            std.log.err("libarchive returned failure {d}: {s}", .{ res, err });
            return ArchiveError.Fatal;
        },
    }
}

fn strip_components(path: [*c]const u8) ?[*c]const u8 {
    const first_slash = std.mem.indexOfScalar(u8, path, '/') orelse return null;
    for (first_slash + 1..path.len) |idx| {
        if (path[idx] == 0) return null;
        if (path[idx] != '/') return path[idx..path.len];
    }
    unreachable;
}

pub fn extract(allocator: std.mem.Allocator, file_name: []const u8) !void {
    const archive = libarchive.archive_read_new() orelse @panic("archive_read_new() failed");
    defer {
        libarchive.archive_read_close(archive);
        libarchive.archive_read_free(archive);
    }

    try check(libarchive.archive_read_support_format_all(archive));
    try check(libarchive.archive_read_support_filter_all(archive));

    const c_file_name = try allocator.dupeZ(file_name);
    defer allocator.free(c_file_name);

    // default block size from bsdtar
    try check(libarchive.archive_read_open_filename(archive, c_file_name, 20 * 512));

    while (true) {
        var entry: *libarchive.archive_entry = null;
        check(libarchive.archive_read_next_header(archive, &entry)) catch |err| switch (err) {
            .Eof => return,
            .Retry => continue,
            else => return err,
        };

        // remove components before the first slash to ensure we extract
        // without creating sub-directories
        if (strip_components(libarchive.archive_entry_pathname())) |path| {
            libarchive.archive_entry_copy_pathname(path);
        }
        if (libarchive.archive_entry_hardlink(entry)) |hardlink| {
            if (strip_components(hardlink)) |path| {
                libarchive.archive_entry_copy_hardlink(path);
            }
        }

        // basic security flags + defaults from bsdtar
        const flags = libarchive.ARCHIVE_EXTRACT_SECURE_SYMLINKS |
            libarchive.ARCHIVE_EXTRACT_SECURE_NODOTDOT |
            libarchive.ARCHIVE_EXTRACT_NO_OVERWRITE |
            libarchive.ARCHIVE_EXTRACT_TIME;
        while (true) {
            check(libarchive.archive_read_extract(archive, entry, flags)) catch |err| {
                if (err == .Retry) continue;
                return err;
            };
            break;
        }
    }
}

pub fn is_extractable(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '.');
    var last_component: ?[]const u8 = null;
    while (it.next()) |ext| {
        if (it.peek() == null) {
            return (
                // file.tar
                std.mem.eql(u8, ext, "tar") ||
                    // file.tar.{gz,zst,...}
                    std.mem.eql(u8, last_component orelse "", "tar") ||
                    // file.t{g,...}z
                    (ext.len == 3 and ext[0] == 't' and ext[2] == 'z'));
        }
        last_component = ext;
    }

    return false;
}
