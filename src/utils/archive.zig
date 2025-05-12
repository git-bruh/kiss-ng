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
fn check(archive: ?*libarchive.struct_archive, res: c_int) ArchiveError!void {
    const err = libarchive.archive_error_string(archive);

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

fn strip_path_components(path: [*c]const u8) ?[*c]const u8 {
    const first_slash = blk: {
        var idx: usize = 0;
        while (true) {
            if (path[idx] == 0) break;
            if (path[idx] == '/') break :blk idx;
            idx += 1;
        }
        return null;
    };

    var idx = first_slash;
    while (true) {
        if (path[idx] == 0) return null;
        if (path[idx] != '/') return &path[idx];
        idx += 1;
    }

    unreachable;
}

pub fn extract(dir: std.fs.Dir, file: std.fs.File, strip_components: bool) !void {
    var cwd = try std.fs.cwd().openDir(".", .{});
    defer {
        std.posix.fchdir(cwd.fd) catch |err| std.log.err("failed to change to original dir after extract: {}", .{err});
        cwd.close();
    }
    try std.posix.fchdir(dir.fd);

    const archive = libarchive.archive_read_new() orelse @panic("archive_read_new() failed");
    defer if (libarchive.archive_read_free(archive) != libarchive.ARCHIVE_OK) @panic("archive_read_free() failed");

    try check(archive, libarchive.archive_read_support_format_all(archive));
    try check(archive, libarchive.archive_read_support_filter_all(archive));

    // default block size from bsdtar
    try check(archive, libarchive.archive_read_open_fd(archive, file.handle, 20 * 512));

    while (true) {
        var entry: ?*libarchive.archive_entry = null;
        check(archive, libarchive.archive_read_next_header(archive, &entry)) catch |err| switch (err) {
            ArchiveError.Eof => return,
            ArchiveError.Retry => continue,
            else => return err,
        };

        if (strip_components) {
            // remove components before the first slash to ensure we extract
            // without creating sub-directories
            if (strip_path_components(libarchive.archive_entry_pathname(entry))) |path| {
                libarchive.archive_entry_copy_pathname(entry, path);
            } else {
                continue;
            }

            if (libarchive.archive_entry_hardlink(entry)) |hardlink| {
                if (strip_path_components(hardlink)) |path| {
                    libarchive.archive_entry_copy_hardlink(entry, path);
                } else {
                    continue;
                }
            }
        }

        // basic security flags + defaults from bsdtar
        const flags = libarchive.ARCHIVE_EXTRACT_SECURE_SYMLINKS |
            libarchive.ARCHIVE_EXTRACT_SECURE_NODOTDOT |
            libarchive.ARCHIVE_EXTRACT_NO_OVERWRITE |
            libarchive.ARCHIVE_EXTRACT_TIME;
        while (true) {
            check(archive, libarchive.archive_read_extract(archive, entry, flags)) catch |err| {
                if (err == ArchiveError.Retry) continue;
                return err;
            };
            break;
        }
    }
}

pub fn compress(dir: std.fs.Dir, file: std.fs.File) !void {
    var cwd = try std.fs.cwd().openDir(".", .{});
    defer {
        std.posix.fchdir(cwd.fd) catch |err| std.log.err("failed to change to original dir after compress: {}", .{err});
        cwd.close();
    }
    try std.posix.fchdir(dir.fd);

    const archive = libarchive.archive_write_new() orelse @panic("archive_write_new() failed");
    defer if (libarchive.archive_write_free(archive) != libarchive.ARCHIVE_OK) @panic("archive_write_free() failed");

    try check(archive, libarchive.archive_write_set_format_ustar(archive));
    try check(archive, libarchive.archive_write_add_filter_zstd(archive));

    try check(archive, libarchive.archive_write_open_fd(archive, file.handle));
    defer if (libarchive.archive_write_close(archive) != libarchive.ARCHIVE_OK) @panic("archive_write_close() failed");

    const resolver = libarchive.archive_entry_linkresolver_new() orelse @panic("archive_entry_linkresolver_new() failed");
    defer libarchive.archive_entry_linkresolver_free(resolver);
    libarchive.archive_entry_linkresolver_set_strategy(resolver, libarchive.ARCHIVE_FORMAT_TAR_USTAR);

    const disk = libarchive.archive_read_disk_new() orelse @panic("archive_read_disk_new() failed");
    defer if (libarchive.archive_read_free(disk) != libarchive.ARCHIVE_OK) @panic("archive_read_free() failed");
    try check(disk, libarchive.archive_read_disk_set_symlink_physical(disk));
    try check(disk, libarchive.archive_read_disk_set_standard_lookup(disk));
    try check(disk, libarchive.archive_read_disk_open(disk, "."));

    while (true) {
        if (libarchive.archive_read_disk_can_descend(disk) == 1) try check(disk, libarchive.archive_read_disk_descend(disk));

        var entry: ?*libarchive.archive_entry = null;
        check(disk, libarchive.archive_read_next_header(disk, &entry)) catch |err| {
            if (err == ArchiveError.Eof) break;
            return err;
        };

        var sparse_entry: ?*libarchive.archive_entry = null;
        libarchive.archive_entry_linkify(resolver, &entry, &sparse_entry);
        if (sparse_entry != null) @panic("sparse_entry is not null");

        try check(archive, libarchive.archive_write_header(archive, entry));
        if (libarchive.archive_entry_size(entry) <= 0) continue;

        var buf: [4096]u8 = undefined;

        while (true) {
            const bytes_read = libarchive.archive_read_data(disk, &buf, buf.len);
            if (bytes_read == 0) break;
            if (bytes_read < 0) {
                check(archive, @intCast(bytes_read)) catch |err| switch (err) {
                    ArchiveError.Retry => continue,
                    ArchiveError.Eof => break,
                    else => return err,
                };
            }

            const bytes_written = libarchive.archive_write_data(archive, &buf, @intCast(bytes_read));
            if (bytes_written < 0) try check(archive, @intCast(bytes_written));
            if (bytes_written < bytes_read) {
                std.log.err("read {d} bytes but wrote only {d}: {s}", .{ bytes_read, bytes_written, libarchive.archive_entry_pathname(entry) });
                return ArchiveError.Fatal;
            }
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
                std.mem.eql(u8, ext, "tar") or
                    // file.tar.{gz,zst,...}
                    std.mem.eql(u8, last_component orelse "", "tar") or
                    // file.t{g,...}z
                    (ext.len == 3 and ext[0] == 't' and ext[2] == 'z'));
        }
        last_component = ext;
    }

    return false;
}
