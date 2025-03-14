const std = @import("std");

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

pub fn main() !void {
    std.log.info(
        "Soon™️",
        .{},
    );
}
