const std = @import("std");
const fs = @import("./fs.zig");

/// iterates over all ELF files in the directory structure
pub const ElfIterator = struct {
    allocator: std.mem.Allocator,

    // list of system paths that the ELF objects link to
    needed_lib_paths: std.ArrayList([]const u8),
    // list of static ELF objects
    static_artifacts: std.ArrayList([]const u8),
    // list of dynamic ELF objects
    dynamic_artifacts: std.ArrayList([]const u8),

    // libraries that have already been checked
    visited_libs: std.StringHashMap(void),

    // temporary variable re-used across invocations
    // used to store offsets for ELF sections
    needed_offsets: std.ArrayList(std.elf.Elf64_Addr),
    // temporary variable re-used across invocations
    // contains libraries that should be extracted from `ldd` output
    libs_to_check: std.StringHashMap(void),

    pub fn new(arena: *std.heap.ArenaAllocator) ElfIterator {
        const allocator = arena.allocator();
        return .{
            .allocator = allocator,
            .needed_lib_paths = .{},
            .static_artifacts = .{},
            .dynamic_artifacts = .{},
            .visited_libs = std.StringHashMap(void).init(allocator),
            .needed_offsets = .{},
            .libs_to_check = std.StringHashMap(void).init(allocator),
        };
    }

    fn parse_file(self: *ElfIterator, file_name: []const u8) !void {
        // prevent needless re-allocation of arrays
        self.needed_offsets.clearRetainingCapacity();
        self.libs_to_check.clearRetainingCapacity();

        // the path is absolute because we later pass it to the `strip` command
        var file = try std.fs.openFileAbsolute(file_name, .{});
        defer file.close();

        var reader_buf: [std.fs.max_path_bytes]u8 = undefined;
        var file_reader = file.reader(&reader_buf);

        const header = std.elf.Header.read(&file_reader.interface) catch |err| switch (err) {
            error.InvalidElfMagic => {
                // !<arch> for .a files
                var ar_header: [8]u8 = undefined;
                file.seekTo(0) catch return;
                _ = file.readAll(&ar_header) catch return;

                if (std.mem.eql(u8, &ar_header, "!<arch>\n")) {
                    std.log.info("got static archive {ks}", .{file_name});
                    try self.static_artifacts.append(self.allocator, file_name);
                }

                return;
            },
            error.EndOfStream => return,
            else => return err,
        };

        std.log.info("inspecting ELF {ks} of type {}", .{ file_name, header.type });

        switch (header.type) {
            // object files (.o), static libraries (.a)
            // no need to compute dependencies
            .REL => {
                try self.static_artifacts.append(self.allocator, file_name);
                return;
            },
            // binaries
            .EXEC => try self.dynamic_artifacts.append(self.allocator, file_name),
            // shared libraries
            .DYN => try self.dynamic_artifacts.append(self.allocator, file_name),
            else => return,
        }

        var load_addr: ?std.elf.Elf64_Addr = null;
        var load_offset: ?std.elf.Elf64_Off = null;

        var prog_it = header.iterateProgramHeaders(&file_reader);
        while (try prog_it.next()) |section| {
            if (section.p_type == std.elf.PT_LOAD) {
                if (load_addr != null or load_offset != null) continue;

                load_addr = section.p_vaddr;
                load_offset = section.p_offset;

                continue;
            }

            if (section.p_type != std.elf.PT_DYNAMIC) continue;

            var rpath_offset: ?std.elf.Elf64_Off = null;
            var strtab_offset: ?std.elf.Elf64_Off = null;

            var idx: u32 = 0;
            while (true) {
                var dyn_buf: [@sizeOf(std.elf.Elf64_Dyn)]u8 align(@alignOf(std.elf.Elf64_Dyn)) = undefined;
                try file_reader.seekTo(section.p_offset + (idx * @sizeOf(std.elf.Elf64_Dyn)));
                try file_reader.interface.readSliceAll(&dyn_buf);

                defer idx += 1;

                const dyn = @as(*const std.elf.Elf64_Dyn, @ptrCast(&dyn_buf));
                switch (dyn.d_tag) {
                    std.elf.DT_NULL => break,
                    std.elf.DT_STRTAB => strtab_offset = (load_offset.? + dyn.d_val) - load_addr.?,
                    std.elf.DT_NEEDED => try self.needed_offsets.append(self.allocator, dyn.d_val),
                    std.elf.DT_RPATH => rpath_offset = dyn.d_val,
                    std.elf.DT_RUNPATH => rpath_offset = dyn.d_val,
                    else => {},
                }
            }

            if (rpath_offset) |off| {
                try file_reader.seekTo(strtab_offset.? + off);

                const rpath = try file_reader.interface.takeDelimiter(0);
                if (!std.mem.eql(u8, rpath.?, "$ORIGIN") or !std.mem.eql(u8, rpath.?, "${ORIGIN}")) {
                    std.log.warn("not checking dependencies for {ks} due to RPATH {ks}", .{ file_name, rpath.? });
                    return;
                }
            }

            for (self.needed_offsets.items) |off| {
                try file_reader.seekTo(strtab_offset.? + off);
                const needed_lib = try file_reader.interface.takeDelimiter(0);
                if (self.visited_libs.contains(needed_lib.?)) continue;
                try self.libs_to_check.put(try self.allocator.dupe(u8, needed_lib.?), {});
            }

            if (self.libs_to_check.count() > 0) {
                var lddC = std.process.Child.init(&.{ "ldd", file_name }, self.allocator);
                lddC.stdout_behavior = .Pipe;
                lddC.stderr_behavior = .Ignore;

                try lddC.spawn();

                var poller = std.io.poll(self.allocator, enum { stdout }, .{
                    .stdout = lddC.stdout.?,
                });
                defer poller.deinit();

                while (try poller.poll()) {}

                var reader = poller.reader(.stdout);

                while (true) {
                    // takeDelimiter returns null on EOF, so we break
                    const lib_mapping = sliceUntilWhitespace((reader.takeDelimiter('\n') catch break) orelse break);

                    // libzstd.so.1 => /lib/libzstd.so.1 (0x7f33a3d35000)
                    var it = std.mem.splitScalar(u8, lib_mapping, ' ');
                    // libzstd.so.1
                    const lib_name = it.next() orelse continue;
                    // =>
                    _ = it.next() orelse continue;
                    // /lib/libzstd.so.1
                    const lib_path = it.next() orelse continue;
                    if (lib_path.len == 0 or lib_path[0] != '/') continue;

                    // we only want to consider DT_NEEDED dependencies, not transitive ones
                    if (self.libs_to_check.get(lib_name) == null) continue;

                    const put_res = try self.visited_libs.getOrPut(try self.allocator.dupe(u8, lib_name));
                    // don't append the same library path again
                    if (put_res.found_existing) continue;

                    // this will be automatically freed with the pool
                    var buf: [std.fs.max_path_bytes]u8 = undefined;
                    const resolved_path = std.fs.realpath(lib_path, &buf) catch |err| {
                        std.log.err("not able to resolve path {ks}: {}", .{ lib_path, err });
                        continue;
                    };
                    try self.needed_lib_paths.append(self.allocator, try self.allocator.dupe(u8, resolved_path));
                }

                _ = try lddC.wait();
            }

            break;
        }
    }

    pub fn walk(self: *ElfIterator, dir: std.fs.Dir) !void {
        var dir_name_buf: [std.fs.max_path_bytes]u8 = undefined;
        var it = dir.iterate();
        while (try it.next()) |entry| {
            switch (entry.kind) {
                .directory => {
                    var sub_dir = try dir.openDir(entry.name, .{ .iterate = true });
                    defer sub_dir.close();

                    try self.walk(sub_dir);
                },
                .file => {
                    const file_name_buf = try self.allocator.alloc(u8, std.fs.max_path_bytes);
                    try self.parse_file(try std.fmt.bufPrint(
                        file_name_buf,
                        "{s}/{s}",
                        .{ try fs.readLink(dir.fd, &dir_name_buf), entry.name },
                    ));
                },
                // symlink / not a regular file
                else => continue,
            }
        }
    }

    /// strips the static & dynamic artifacts
    pub fn finalize(self: *ElfIterator, strip: bool) ![][]const u8 {
        if (!strip) return self.needed_lib_paths.items;

        // strip -<g|s> -R .comment -R .note <...>
        const base_len = 6;
        var args_buf = try self.allocator.alloc([]const u8, base_len + @max(self.static_artifacts.items.len, self.dynamic_artifacts.items.len));
        defer self.allocator.free(args_buf);

        const args: []const []const u8 = &.{ "strip", "-g", "-R", ".comment", "-R", ".note" };

        @memcpy(args_buf[0..args.len], args);

        if (self.static_artifacts.items.len > 0) {
            @memcpy(args_buf[base_len .. base_len + self.static_artifacts.items.len], self.static_artifacts.items);

            var stripC = std.process.Child.init(args_buf[0 .. base_len + self.static_artifacts.items.len], self.allocator);
            stripC.stdout_behavior = .Ignore;
            _ = try stripC.spawnAndWait();
        }

        if (self.dynamic_artifacts.items.len > 0) {
            // we can't use -g for dynamic libraries because it will also strip
            // the dynamic symbol entries
            args_buf[1] = "-s";
            @memcpy(args_buf[base_len .. base_len + self.dynamic_artifacts.items.len], self.dynamic_artifacts.items);
            var stripC = std.process.Child.init(args_buf[0 .. base_len + self.dynamic_artifacts.items.len], self.allocator);
            stripC.stdout_behavior = .Ignore;
            _ = try stripC.spawnAndWait();
        }

        return self.needed_lib_paths.items;
    }

    pub fn free(self: *ElfIterator) void {
        self.needed_lib_paths.deinit(self.allocator);
        self.static_artifacts.deinit(self.allocator);
        self.dynamic_artifacts.deinit(self.allocator);
        self.visited_libs.deinit();
        self.needed_offsets.deinit(self.allocator);
        self.libs_to_check.deinit();
    }
};

fn sliceUntilWhitespace(contents: []const u8) []const u8 {
    var idx: usize = 0;
    while (idx < contents.len) : (idx += 1) {
        if (!std.ascii.isWhitespace(contents[idx])) return contents[idx..];
    }
    return contents;
}
