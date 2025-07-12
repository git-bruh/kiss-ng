const std = @import("std");
const fs = @import("fs.zig");
const landlock = @cImport({
    @cInclude("linux/landlock.h");
    @cInclude("syscall.h");
});

pub const Permissions = struct {
    pub const Read = landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR;
    pub const ReadDir = landlock.LANDLOCK_ACCESS_FS_READ_DIR;

    pub const Write = landlock.LANDLOCK_ACCESS_FS_WRITE_FILE | landlock.LANDLOCK_ACCESS_FS_REMOVE_DIR | landlock.LANDLOCK_ACCESS_FS_REMOVE_FILE | landlock.LANDLOCK_ACCESS_FS_MAKE_CHAR | landlock.LANDLOCK_ACCESS_FS_MAKE_DIR | landlock.LANDLOCK_ACCESS_FS_MAKE_REG | landlock.LANDLOCK_ACCESS_FS_MAKE_SOCK | landlock.LANDLOCK_ACCESS_FS_MAKE_FIFO | landlock.LANDLOCK_ACCESS_FS_MAKE_BLOCK | landlock.LANDLOCK_ACCESS_FS_MAKE_SYM | landlock.LANDLOCK_ACCESS_FS_REFER | landlock.LANDLOCK_ACCESS_FS_TRUNCATE;
    pub const Execute = landlock.LANDLOCK_ACCESS_FS_EXECUTE;
};

const ALL_FILE_PERMS = landlock.LANDLOCK_ACCESS_FS_EXECUTE | landlock.LANDLOCK_ACCESS_FS_WRITE_FILE | landlock.LANDLOCK_ACCESS_FS_READ_FILE;

const LandlockError = error{
    LandlockNotSupported,
    TcpNotSupported,
    InvalidArgument,
    EmptyAccesses,
    BadFileDescriptor,
    PermissionError,
    TooManyRulesets,
};

fn landlock_create_ruleset(attr: *const landlock.landlock_ruleset_attr, flags: u32) LandlockError!std.posix.fd_t {
    const ret = std.os.linux.syscall3(std.os.linux.syscalls.X64.landlock_create_ruleset, @intFromPtr(attr), @sizeOf(landlock.landlock_ruleset_attr), flags);
    switch (std.posix.errno(ret)) {
        .SUCCESS => return @intCast(ret),
        .OPNOTSUPP => return error.LandlockNotSupported,
        .INVAL => return error.InvalidArgument,
        .@"2BIG" => unreachable,
        .FAULT => unreachable,
        .NOMSG => return error.EmptyAccesses,
        else => unreachable,
    }
}

fn landlock_add_rule(ruleset_fd: std.posix.fd_t, rule_type: landlock.landlock_rule_type, rule_attr: *const landlock.landlock_path_beneath_attr, flags: u32) LandlockError!void {
    switch (std.posix.errno(std.os.linux.syscall4(std.os.linux.syscalls.X64.landlock_add_rule, @intCast(ruleset_fd), rule_type, @intFromPtr(rule_attr), flags))) {
        .SUCCESS => return,
        .AFNOSUPPORT => return error.TcpNotSupported,
        .OPNOTSUPP => return error.LandlockNotSupported,
        .INVAL => return error.InvalidArgument,
        .NOMSG => return error.EmptyAccesses,
        .BADF => return error.BadFileDescriptor,
        .BADFD => return error.BadFileDescriptor,
        .PERM => return error.PermissionError,
        .FAULT => unreachable,
        else => unreachable,
    }
}

fn landlock_restrict_self(ruleset_fd: std.posix.fd_t, flags: u32) LandlockError!void {
    switch (std.posix.errno(std.os.linux.syscall2(std.os.linux.syscalls.X64.landlock_restrict_self, @as(usize, @intCast(ruleset_fd)), flags))) {
        .SUCCESS => return,
        .OPNOTSUPP => return error.LandlockNotSupported,
        .INVAL => return error.InvalidArgument,
        .BADF => return error.BadFileDescriptor,
        .BADFD => return error.BadFileDescriptor,
        .PERM => return error.PermissionError,
        .@"2BIG" => return error.TooManyRulesets,
        else => unreachable,
    }
}

pub const Landlock = struct {
    handle: std.posix.fd_t,

    pub fn init() !Landlock {
        return .{ .handle = try landlock_create_ruleset(&.{
            .handled_access_fs = Permissions.Read | Permissions.Write | Permissions.Execute,
        }, 0) };
    }

    pub fn add_rule(self: *const Landlock, fd: std.posix.fd_t, perms: c_ulonglong) !void {
        const stat = try std.posix.fstat(fd);

        const path_beneath: landlock.landlock_path_beneath_attr = .{
            .parent_fd = fd,
            // exclude file-specific flags in-case of a directory
            // otherwise, only preserve file-specific flags
            .allowed_access = if ((stat.mode & std.c.S.IFMT) == std.c.S.IFDIR) (perms & ~ALL_FILE_PERMS) else (perms & ALL_FILE_PERMS),
        };

        try landlock_add_rule(self.handle, landlock.LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    }

    pub fn add_rule_with_children(self: *const Landlock, fd: std.posix.fd_t, perms: c_ulonglong) !void {
        const path_beneath: landlock.landlock_path_beneath_attr = .{
            .parent_fd = fd,
            // don't filter file / directory permissions as we want to propagate
            // the permissions to all the children
            .allowed_access = perms,
        };

        try landlock_add_rule(self.handle, landlock.LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    }

    pub fn add_rule_at_path(self: *const Landlock, path: []const u8, perms: c_ulonglong) !void {
        const fd = try std.posix.open(path, .{}, 0);
        defer std.posix.close(fd);
        try self.add_rule_with_children(fd, perms);
    }

    pub fn enforce(self: *const Landlock) !void {
        _ = try std.posix.prctl(std.c.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
        try landlock_restrict_self(self.handle, 0);
    }

    pub fn deinit(self: *Landlock) void {
        _ = std.posix.close(self.handle);
    }
};
