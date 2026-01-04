const std = @import("std");
const colors = @import("./colors.zig");
const libcurl = @cImport(@cInclude("curl/curl.h"));

const ProgressData = struct {
    printed: bool,
    begin: std.time.Instant,
};

fn data_cb(ptr: [*c]u8, size: usize, nmemb: usize, userdata: *anyopaque) callconv(.c) usize {
    const file: *std.fs.File = @ptrCast(@alignCast(userdata));
    const slice: []const u8 = @as([*]u8, @ptrCast(ptr))[0 .. size * nmemb];
    file.writeAll(slice) catch |err| {
        std.log.err("failed to write to file: {}", .{err});
        return 0;
    };
    return slice.len;
}

fn progress_cb(userdata: *anyopaque, dltotal: libcurl.curl_off_t, dlnow: libcurl.curl_off_t, ultotal: libcurl.curl_off_t, ulnow: libcurl.curl_off_t) callconv(.c) i32 {
    _ = ultotal;
    _ = ulnow;

    var winsize: std.posix.winsize = undefined;
    const err = std.posix.system.ioctl(std.c.STDOUT_FILENO, std.posix.T.IOCGWINSZ, @intFromPtr(&winsize));
    if (std.posix.errno(err) != .SUCCESS) winsize.col = 80;

    const data: *ProgressData = @ptrCast(@alignCast(userdata));
    data.printed = true;

    const now = std.time.Instant.now() catch unreachable;

    const speed = @as(f64, @floatFromInt(dlnow)) / (@as(f64, @floatFromInt(now.since(data.begin))) / std.time.ns_per_s);
    const time_left = if (dltotal != 0) @as(f64, @floatFromInt(dltotal)) / speed else 0;
    const percentage = if (dltotal != 0) @as(f64, @floatFromInt(dlnow)) / @as(f64, @floatFromInt(dltotal)) else 0;

    // <TOTAL_SIZE> <SPEED> <MM:SS> [###...] <PERCENTAGE>
    var buffer: [512]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buffer, "\r{d} MB  {d:.2} MB/s  {d:02}:{d:02}  ", .{ dltotal >> 20, speed / @as(f64, 1 << 20), @divFloor(time_left, 60), @floor(@mod(time_left, 60)) }) catch unreachable;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    stdout.writeAll(formatted) catch unreachable;

    const bar_len = winsize.col - formatted.len - "[] 100%".len;
    const bar_to_fill = @as(u64, @intFromFloat(percentage * @as(f64, @floatFromInt(bar_len))));

    stdout.writeAll(colors.KISS_COLOR_SECONDARY ++ "[" ++ colors.KISS_COLOR_CLEAR ++ colors.KISS_COLOR_PRIMARY) catch unreachable;
    for (0..bar_to_fill) |_| {
        stdout.writeAll("#") catch unreachable;
    }
    stdout.writeAll(colors.KISS_COLOR_CLEAR ++ colors.KISS_COLOR_SECONDARY) catch unreachable;
    for (bar_to_fill..bar_len) |_| {
        stdout.writeAll(".") catch unreachable;
    }
    stdout.writeAll("]" ++ colors.KISS_COLOR_CLEAR) catch unreachable;
    stdout.print(" {d: >3}%", .{@as(u64, @intFromFloat(percentage * 100))}) catch unreachable;
    stdout.flush() catch unreachable;

    return 0;
}

pub fn download(allocator: std.mem.Allocator, file: std.fs.File, fetch_url: []const u8) !bool {
    const curl = libcurl.curl_easy_init();
    if (curl == null) {
        std.log.err("curl_easy_init() failed", .{});
        return false;
    }
    defer libcurl.curl_easy_cleanup(curl);

    const url = try allocator.dupeZ(u8, fetch_url);
    defer allocator.free(url);

    const user_agent = try allocator.dupeZ(u8, "curl/8.13.0");
    defer allocator.free(user_agent);

    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_URL, url.ptr);
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_USERAGENT, user_agent.ptr);
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_FOLLOWLOCATION, @as(usize, 1));
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_WRITEFUNCTION, data_cb);
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_WRITEDATA, &file);
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_NOPROGRESS, @as(usize, 0));
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_XFERINFOFUNCTION, progress_cb);
    var data = ProgressData{ .printed = false, .begin = std.time.Instant.now() catch unreachable };
    _ = libcurl.curl_easy_setopt(curl, libcurl.CURLOPT_XFERINFODATA, &data);

    const res = libcurl.curl_easy_perform(curl);
    if (data.printed) std.fs.File.stdout().writeAll("\n") catch unreachable;
    if (res != libcurl.CURLE_OK) {
        std.log.err("curl_easy_perform() failed: {ks}", .{libcurl.curl_easy_strerror(res)});
        return false;
    }

    return true;
}
