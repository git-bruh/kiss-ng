const std = @import("std");

pub fn block_sigint() void {
    var set = std.posix.empty_sigset;
    std.os.linux.sigaddset(&set, std.posix.SIG.INT);
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &set, null);
}

pub fn unblock_sigint() void {
    var set = std.posix.empty_sigset;
    std.os.linux.sigaddset(&set, std.posix.SIG.INT);
    std.posix.sigprocmask(std.posix.SIG.UNBLOCK, &set, null);
}
