const std = @import("std");
const config = @import("config.zig");
const commands = @import("commands.zig");
const pkg_manager = @import("package_manager.zig");

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

fn log(
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

    const fmt_specifier = KISS_COLOR_SECONDARY ++ "{s}" ++ KISS_COLOR_CLEAR;
    comptime var tty_format: [format.len + fmt_specifier.len]u8 = @splat(0);
    _ = comptime std.mem.replace(u8, format, "{ks}", fmt_specifier, &tty_format);

    const fmt_clean = comptime std.fmt.comptimePrint(
        "[{s}] ",
        .{log_level},
    ) ++ clean_format ++ "\n";

    const fmt_tty = comptime std.fmt.comptimePrint(
        "{s}[{s}]{s} ",
        .{
            KISS_COLOR_PRIMARY, log_level, KISS_COLOR_CLEAR,
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

pub fn main() !void {
    if (std.os.argv.len < 2) {
        try std.io.getStdOut().writer().print(
            \\-> kiss [a|b|c|d|i|l|p|r|s|u|U|v] [pkg]... 
            \\-> alternatives List and swap alternatives 
            \\-> build        Build packages 
            \\-> checksum     Generate checksums 
            \\-> download     Download sources 
            \\-> install      Install packages 
            \\-> list         List installed packages 
            \\-> preferred    List owners of files with alternatives 
            \\-> remove       Remove packages 
            \\-> search       Search for packages 
            \\-> update       Update the repositories 
            \\-> upgrade      Update the system 
            \\-> version      Package manager version 
            \\
        , .{});
        std.process.exit(0);
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer if (gpa.deinit() == .leak) unreachable;

    var pkg_man = pkg_manager.PackageManager.new(allocator, try config.Config.new_from_env(allocator));
    defer pkg_man.free();

    const args = try allocator.alloc([]const u8, std.os.argv.len - 1);
    defer allocator.free(args);

    for (std.os.argv[1..], 0..) |arg, idx| {
        args[idx] = std.mem.sliceTo(arg, 0);
    }

    const command = commands.parse_command(args) catch std.process.exit(1);
    try pkg_man.handle(command);
}
