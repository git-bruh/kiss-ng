const std = @import("std");

pub fn repoRoot(allocator: std.mem.Allocator, git_dir: std.fs.Dir) !?std.ArrayListUnmanaged(u8) {
    var revParseC = std.process.Child.init(&.{ "git", "rev-parse", "--show-toplevel" }, allocator);

    revParseC.cwd_dir = git_dir;
    revParseC.stdout_behavior = .Pipe;
    revParseC.stderr_behavior = .Pipe;

    try revParseC.spawn();

    const buf_size = 1024;

    var repo_path = try std.ArrayListUnmanaged(u8).initCapacity(allocator, buf_size);
    errdefer repo_path.deinit(allocator);

    var stderr = try std.ArrayListUnmanaged(u8).initCapacity(allocator, buf_size);
    defer stderr.deinit(allocator);

    try revParseC.collectOutput(allocator, &repo_path, &stderr, buf_size);

    if (code(try revParseC.wait()) != 0) {
        repo_path.deinit(allocator);
        return null;
    }

    return repo_path;
}

pub fn pull(allocator: std.mem.Allocator, git_dir: std.fs.Dir) !bool {
    return try spawnAndWait(allocator, &.{ "git", "pull" }, git_dir, false) == 0;
}

pub fn initAndPull(allocator: std.mem.Allocator, git_dir: std.fs.Dir, clone_url: []const u8, commit_hash: ?[]const u8) !bool {
    const initialized = blk: {
        git_dir.access(".git", .{}) catch break :blk false;
        break :blk true;
    };

    if (!initialized and try spawnAndWait(allocator, &.{ "git", "init" }, git_dir, false) != 0) {
        return false;
    }

    var status = try spawnAndWait(allocator, &.{ "git", "remote", "set-url", "origin", clone_url }, git_dir, true);
    if (status != 0) {
        status = try spawnAndWait(allocator, &.{ "git", "remote", "add", "origin", clone_url }, git_dir, false);
        if (status != 0) {
            return false;
        }
    }

    status = try spawnAndWait(allocator, &.{ "git", "fetch", "--depth=1", "origin", commit_hash orelse "" }, git_dir, false);
    if (status != 0) {
        return false;
    }

    status = try spawnAndWait(allocator, &.{ "git", "reset", "--hard", "FETCH_HEAD" }, git_dir, false);
    if (status != 0) {
        return false;
    }

    return true;
}

fn spawnAndWait(allocator: std.mem.Allocator, cmd: []const []const u8, cwd: std.fs.Dir, ignore_stderr: bool) !u8 {
    var child = std.process.Child.init(cmd, allocator);
    child.cwd_dir = cwd;
    if (ignore_stderr) {
        child.stderr_behavior = .Ignore;
    }
    return code(try child.spawnAndWait());
}

fn code(result: std.process.Child.Term) u8 {
    if (result != .Exited) {
        @panic("process didn't terminate as expected");
    }
    return result.Exited;
}
