const std = @import("std");

/// A dependency can either be build time (needed just for building the package)
/// or runtime (needed both at build time and runtime)
/// They are read from the newline delimited `depends` file
///
/// cmake make
/// linux-headers make
/// openssl
/// zlib
const Dependency = struct {
    name: []const u8,
    kind: enum { Build, Runtime },
};

/// Source can be fetched via various methods, like from a Git repo, an HTTP url
/// or a local file path. They are read from the newline-delimited `sources` file
///
/// 1. Git (URL + Commit):
///     git+https://sourceware.org/git/glibc.git#1e04dcec491bd8f48b5b74ce3e8414132578a645
///
/// 2. Http (URL, optionally specifying the directory for extraction/relocation):
///     https://ftp.mozilla.org/pub/firefox/releases/119.0/source/firefox-119.0.source.tar.xz
///     https://github.com/jedisct1/libhydrogen/archive/a4de6e098b5bbbd5389eb8058130f782b53826c3.tar.gz libhydrogen
///
/// 3. Local (Relative path on filesystem, optionally specifying directory in build tree):
///     patches/fix-build.patch
///     files/config extras
const Source = union(enum) {
    Git: struct {
        build_path: ?[]const u8,
        clone_url: []const u8,
        commit_hash: ?[]const u8,
    },
    Http: struct {
        build_path: ?[]const u8,
        fetch_url: []const u8,
        checksum: []const u8,
    },
    Local: struct {
        build_path: ?[]const u8,
        path: []const u8,
        checksum: []const u8,
    },
};

/// A package present in a KISS repository is a directory structure providing
/// metadata for building/installing via individual files
///
///  1. build: An executable file (usually shell scripts) to be run in the
///            constructed build environment
///  2. checksums: A list of BLAKE3 checksums corresponding to the sources file
///  3. depends: A list of other dependencies, each of which are parsed into `Dependency`
///  4. sources: A list of sources required for building the package, parsed into `Source`
///  5. version: Version of the package, can be any arbritary string
pub const Package = struct {
    name: []const u8,
    version: []const u8,
    // backing allocated content for sources and dependencies
    backing_contents: [3][]const u8,
    dependencies: std.ArrayList(Dependency),
    sources: std.ArrayList(Source),
    dir: std.fs.Dir,
    allocator: std.mem.Allocator,

    pub fn new(allocator: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) !Package {
        const version = try read_until_end(allocator, dir, "version");
        errdefer allocator.free(version);

        const depends = try read_until_end(allocator, dir, "depends");
        errdefer allocator.free(depends);

        const sources = try read_until_end(allocator, dir, "sources");
        errdefer allocator.free(sources);

        const checksums = try read_until_end(allocator, dir, "checksums");
        errdefer allocator.free(checksums);

        const sourcesArray = try parse_sources(allocator, sources, checksums);
        errdefer sourcesArray.deinit();

        const dependencies = try parse_dependencies(allocator, depends);
        errdefer dependencies.deinit();

        return Package{
            .name = try allocator.dupe(u8, name),
            .version = version,
            .backing_contents = .{ depends, sources, checksums },
            .dependencies = dependencies,
            .sources = sourcesArray,
            .dir = dir,
            .allocator = allocator,
        };
    }

    pub fn free(self: *Package) void {
        self.allocator.free(self.name);
        self.allocator.free(self.version);
        for (self.backing_contents) |bytes| {
            self.allocator.free(bytes);
        }
        self.dependencies.deinit();
        self.sources.deinit();
        self.dir.close();
    }
};

fn parse_sources(allocator: std.mem.Allocator, sources: []const u8, checksums: []const u8) !std.ArrayList(Source) {
    var sourceIter = std.mem.splitScalar(u8, sources, '\n');
    var checksumIter = std.mem.splitScalar(u8, checksums, '\n');

    var sourceArray = std.ArrayList(Source).init(allocator);
    errdefer sourceArray.deinit();

    while (sourceIter.next()) |sourceBuf| {
        var iter = std.mem.splitScalar(u8, sourceBuf, ' ');

        const source = iter.next() orelse unreachable;
        const build_path = iter.next();

        if (std.mem.startsWith(u8, source, "git+")) {
            var cloneCommitIter = std.mem.splitScalar(u8, source, '#');

            const cloneUrl = cloneCommitIter.next() orelse unreachable;
            const commitHash = cloneCommitIter.next();

            try sourceArray.append(.{
                .Git = .{ .build_path = build_path, .clone_url = cloneUrl, .commit_hash = commitHash },
            });
            continue;
        }

        const checksum = checksumIter.next() orelse unreachable;

        if (std.mem.containsAtLeast(u8, source, 1, "://")) {
            try sourceArray.append(.{
                .Http = .{ .build_path = build_path, .fetch_url = source, .checksum = checksum },
            });
        } else {
            try sourceArray.append(.{
                .Local = .{ .build_path = build_path, .path = source, .checksum = checksum },
            });
        }
    }

    return sourceArray;
}

fn parse_dependencies(allocator: std.mem.Allocator, depends: []const u8) !std.ArrayList(Dependency) {
    var dependencies = std.ArrayList(Dependency).init(allocator);

    var iter = std.mem.splitScalar(u8, depends, '\n');
    while (iter.next()) |dependency| {
        var nameMakeIter = std.mem.splitScalar(u8, dependency, ' ');
        const name = nameMakeIter.next() orelse unreachable;
        try dependencies.append(Dependency{
            .name = name,
            .kind = if (nameMakeIter.next() == null) .Runtime else .Build,
        });
    }

    return dependencies;
}

fn read_until_end(allocator: std.mem.Allocator, dir: std.fs.Dir, name: []const u8) ![]const u8 {
    const file = try dir.openFile(name, .{});
    defer file.close();

    return try file.readToEndAlloc(allocator, 1 << 16);
}
