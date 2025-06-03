const std = @import("std");
const fs = @import("./fs.zig");

/// iterates over all ELF files in the directory structure
pub const ElfIterator = struct {
    allocator: std.mem.Allocator,
    pool: std.heap.MemoryPool([std.fs.max_path_bytes]u8),

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
    libs_to_check: std.ArrayList([]const u8),

    pub fn new(allocator: std.mem.Allocator) ElfIterator {
        return .{
            .allocator = allocator,
            .pool = std.heap.MemoryPool([std.fs.max_path_bytes]u8).init(allocator),
            .needed_lib_paths = std.ArrayList([]const u8).init(allocator),
            .static_artifacts = std.ArrayList([]const u8).init(allocator),
            .dynamic_artifacts = std.ArrayList([]const u8).init(allocator),
            .visited_libs = std.StringHashMap(void).init(allocator),
            .needed_offsets = std.ArrayList(std.elf.Elf64_Addr).init(allocator),
            .libs_to_check = std.ArrayList([]const u8).init(allocator),
        };
    }

    fn parse_file(self: *ElfIterator, file_name: []const u8) !void {
        // prevent needless re-allocation of arrays
        self.needed_offsets.clearRetainingCapacity();
        self.libs_to_check.clearRetainingCapacity();

        // the path is absolute because we later pass it to the `strip` command
        var file = try std.fs.openFileAbsolute(file_name, .{});
        defer file.close();

        // TODO this seems to break for .a files
        const header = std.elf.Header.read(file) catch |err| switch (err) {
            error.InvalidElfMagic => return,
            error.EndOfStream => return,
            else => return err,
        };

        std.log.info("inspecting ELF {ks} of type {}", .{ file_name, header.type });

        switch (header.type) {
            // object files (.o), static libraries (.a)
            // no need to compute dependencies
            .REL => {
                try self.static_artifacts.append(file_name);
                return;
            },
            // binaries
            .EXEC => try self.dynamic_artifacts.append(file_name),
            // shared libraries
            .DYN => try self.dynamic_artifacts.append(file_name),
            else => return,
        }

        var load_addr: ?std.elf.Elf64_Addr = null;
        var load_offset: ?std.elf.Elf64_Off = null;

        var prog_it = header.program_header_iterator(file);
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
                try file.seekableStream().seekTo(section.p_offset + (idx * @sizeOf(std.elf.Elf64_Dyn)));
                try file.reader().readNoEof(&dyn_buf);

                defer idx += 1;

                const dyn = @as(*const std.elf.Elf64_Dyn, @ptrCast(&dyn_buf));
                switch (dyn.d_tag) {
                    std.elf.DT_NULL => break,
                    std.elf.DT_STRTAB => strtab_offset = (load_offset.? + dyn.d_val) - load_addr.?,
                    std.elf.DT_NEEDED => try self.needed_offsets.append(dyn.d_val),
                    std.elf.DT_RPATH => rpath_offset = dyn.d_val,
                    std.elf.DT_RUNPATH => rpath_offset = dyn.d_val,
                    else => {},
                }
            }

            if (rpath_offset) |off| {
                try file.seekableStream().seekTo(strtab_offset.? + off);

                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const rpath = try file.reader().readUntilDelimiter(&buf, 0);

                if (!std.mem.eql(u8, rpath, "$ORIGIN") or !std.mem.eql(u8, rpath, "${ORIGIN}")) {
                    std.log.warn("not checking dependencies for {ks} due to RPATH {ks}", .{ file_name, rpath });
                    return;
                }
            }

            for (self.needed_offsets.items) |off| {
                try file.seekableStream().seekTo(strtab_offset.? + off);
                const buf = try self.pool.create();

                const needed_lib = file.reader().readUntilDelimiter(buf, 0) catch |e| {
                    self.pool.destroy(buf);
                    return e;
                };
                if (self.visited_libs.contains(needed_lib)) {
                    self.pool.destroy(buf);
                    continue;
                }

                try self.visited_libs.put(needed_lib, {});
                try self.libs_to_check.append(needed_lib);
            }

            if (self.libs_to_check.items.len > 0) {
                var lddC = std.process.Child.init(&.{ "ldd", file_name }, self.allocator);
                lddC.stdout_behavior = .Pipe;
                lddC.stderr_behavior = .Ignore;

                try lddC.spawn();

                var poller = std.io.poll(self.allocator, enum { stdout }, .{
                    .stdout = lddC.stdout.?,
                });
                defer poller.deinit();

                while (try poller.poll()) {
                    // this will be automatically freed with the pool
                    const buf = try self.pool.create();

                    const n = poller.fifo(.stdout).read(buf);
                    if (n == 0) continue;

                    const lib_mapping = buf[0..n];

                    //  libzstd.so.1 => /lib/libzstd.so.1 (0x7f33a3d35000)
                    var it = std.mem.splitScalar(u8, lib_mapping, ' ');
                    // libzstd.so.1
                    const lib_name = it.next() orelse continue;
                    // =>
                    _ = it.next() orelse continue;
                    // /lib/libzstd.so.1
                    const lib_path = it.next() orelse continue;

                    const putRes = try self.visited_libs.getOrPut(lib_name);
                    // don't append the same library path again
                    if (putRes.found_existing) continue;
                    try self.needed_lib_paths.append(lib_path);
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
                    const file_name_buf = try self.pool.create();
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
    pub fn finalize(self: *ElfIterator) ![][]const u8 {
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
        self.pool.deinit();
        self.needed_lib_paths.deinit();
        self.static_artifacts.deinit();
        self.dynamic_artifacts.deinit();
        self.visited_libs.deinit();
        self.needed_offsets.deinit();
        self.libs_to_check.deinit();
    }
};
