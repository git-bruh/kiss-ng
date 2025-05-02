const std = @import("std");
const blake3 = @cImport(@cInclude("blake3.h"));

pub const B3SUM_LEN = 33;
pub const CHECKSUM = [B3SUM_LEN * 2]u8;

pub fn b3sum(file: std.fs.File, out: *[B3SUM_LEN * 2]u8) !void {
    var hasher: blake3.blake3_hasher = undefined;
    blake3.blake3_hasher_init(&hasher);

    var buf: [16384]u8 = undefined;
    while (true) {
        const len = try file.read(&buf);
        blake3.blake3_hasher_update(&hasher, &buf, len);

        // if we didn't read a full chunk then it means we have reached EOF
        if (len != buf.len) {
            break;
        }
    }

    var checksum: [B3SUM_LEN]u8 = undefined;
    blake3.blake3_hasher_finalize(&hasher, &checksum, B3SUM_LEN);

    for (checksum, 0..) |byte, idx| {
        _ = try std.fmt.bufPrint(out[idx * 2 .. (idx * 2) + 2], "{x:02}", .{byte});
    }
}
