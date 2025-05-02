const std = @import("std");
const colors = @import("./colors.zig");

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

    _ = log_scope;

    // Custom {ks} format specifier for highlighting log details
    comptime var clean_format: [format.len]u8 = @splat(0);
    _ = comptime std.mem.replace(u8, format, "{ks}", "{s}", &clean_format);

    const fmt_specifier = colors.KISS_COLOR_SECONDARY ++ "{s}" ++ colors.KISS_COLOR_CLEAR;
    const fmt_count = comptime std.mem.count(u8, format, "{ks}");
    comptime var tty_format: [format.len + (fmt_specifier.len * fmt_count)]u8 = @splat(0);
    _ = comptime std.mem.replace(u8, format, "{ks}", fmt_specifier, &tty_format);

    const fmt_clean = comptime std.fmt.comptimePrint(
        "[{s}] ",
        .{log_level},
    ) ++ clean_format ++ "\n";

    const fmt_tty = comptime std.fmt.comptimePrint(
        "{s}[{s}]{s} ",
        .{
            colors.KISS_COLOR_PRIMARY, log_level, colors.KISS_COLOR_CLEAR,
        },
    ) ++ tty_format ++ "\n";

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();

    const stderr = std.io.getStdErr();
    const writer = stderr.writer();

    (if (stderr.supportsAnsiEscapeCodes())
        writer.print(fmt_tty, args)
    else
        writer.print(fmt_clean, args)) catch return;
}
