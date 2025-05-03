const std = @import("std");
const config = @import("config.zig");
const commands = @import("commands.zig");
const pkg_manager = @import("package_manager.zig");
const logger = @import("utils/log.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logger.log,
};

pub fn main() !u8 {
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

    const command = try commands.parse_command(args);
    return if (try pkg_man.handle(command)) 0 else 1;
}
