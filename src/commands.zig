const std = @import("std");

const PackageArray = ?[][]const u8;

pub const Command = union(enum) {
    Alternatives: ?struct {
        package_name: []const u8,
        file_path: []const u8,
    },
    Build: PackageArray,
    Checksum: PackageArray,
    Download: PackageArray,
    Install: PackageArray,
    List: PackageArray,
    Preferred: ?[]const u8,
    Remove: PackageArray,
    Search: PackageArray,
    Update: void,
    Upgrade: void,
    Version: void,
};

fn slice(str: [*:0]u8) []u8 {
    return std.mem.sliceTo(str, 0);
}

fn anyEqual(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.mem.eql(u8, haystack, needle)) return true;
    }

    return false;
}

pub fn parse_command(args: [][]const u8) !Command {
    const command = args[0];

    if (anyEqual(command, &.{ "a", "alternatives" })) {
        if (args.len < 3) return Command{ .Alternatives = null };

        return Command{ .Alternatives = .{
            .package_name = args[1],
            .file_path = args[2],
        } };
    } else if (anyEqual(command, &.{ "p", "preferred" })) {
        if (args.len < 2) return Command{ .Preferred = null };
        return Command{ .Preferred = args[1] };
    } else if (anyEqual(command, &.{ "u", "update" })) {
        return Command{ .Update = {} };
    } else if (anyEqual(command, &.{ "U", "upgrade" })) {
        return Command{ .Upgrade = {} };
    } else if (anyEqual(command, &.{ "v", "version" })) {
        return Command{ .Version = {} };
    }

    const pkg_array: PackageArray = if (args.len > 1) args[1..] else null;

    if (anyEqual(command, &.{ "b", "build" })) {
        return Command{ .Build = pkg_array };
    } else if (anyEqual(command, &.{ "c", "checksum" })) {
        return Command{ .Checksum = pkg_array };
    } else if (anyEqual(command, &.{ "d", "download" })) {
        return Command{ .Download = pkg_array };
    } else if (anyEqual(command, &.{ "i", "install" })) {
        return Command{ .Install = pkg_array };
    } else if (anyEqual(command, &.{ "l", "list" })) {
        return Command{ .List = pkg_array };
    } else if (anyEqual(command, &.{ "r", "remove" })) {
        return Command{ .Remove = pkg_array };
    } else if (anyEqual(command, &.{ "s", "search" })) {
        return Command{ .Search = pkg_array };
    }

    std.log.err("invalid command: {s}", .{command});
    return error.InvalidArgument;
}
