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
        clone_url: []const u8,
        commit_hash: []const u8,
    },
    Http: struct {
        fetch_url: []const u8,
        build_path: ?[]const u8,
        checksum: ?[]const u8,
    },
    Local: struct {
        path: []const u8,
        build_path: ?[]const u8,
        checksum: ?[]const u8,
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
    build_exe: []const u8,
    version: []const u8,
    dependencies: []Dependency,
    sources: []Source,
};
