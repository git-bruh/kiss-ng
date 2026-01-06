# kiss-ng

Next generation of the [KISS](https://codeberg.org/kiss-community/kiss) package manager, aiming to be more robust and powerful (sandboxed builds, provides system, etc)

The project currently supports almost all of the KISS features and can act as a drop-in replacement for the KISS package manager, with a few differences:

- The package manager is invoked as root for build (`b`), install (`i`) and upgrade (`U`) operations due to the sandboxing mechanism

- Build scripts cannot access the network, packages must be refactored to support vendored / pre-cached dependencies

- All binaries, sources, and logs are stored at `/var/cache/kiss` instead of the cache directory under `$HOME`

# Usage

```sh
$ kiss_ng
-> kiss [a|b|c|d|i|l|p|r|s|u|U|v] [pkg]... 
-> alternatives List and swap alternatives 
-> build        Build packages 
-> checksum     Generate checksums 
-> download     Download sources 
-> install      Install packages 
-> list         List installed packages 
-> preferred    List owners of files with alternatives 
-> remove       Remove packages 
-> search       Search for packages 
-> update       Update the repositories 
-> upgrade      Update the system 
-> version      Package manager version
``` 

# TODO

- [ ] alternatives & choices system
  - [ ] check orphaned alternatives during removal

- [ ] provides system

- [x] build
  - [x] dynamic dependency detection
  - [x] binary stripping
  - [x] sandboxed builds using [`landlock`](https://landlock.io)

- [x] checksum

- [x] download
  - [ ] parallel downloads

- [x] install
  - [ ] conflicts
    - [ ] etcsums
    - [x] files

- [x] list

- [x] remove

- [x] search

- [x] update

- [x] upgrade

- [x] hooks (package-specified only, no user hooks)
  - [x] pre-remove
  - [x] post-install
  - ~~[ ] user hooks~~ not planned

- [x] global lock for installation/removal

- [x] environment variables
  - [x] `KISS_ROOT`
  - ~~[ ] `KISS_COMPRESS`~~ `zstd` compression by default
  - [x] `KISS_PATH`
  - ~~[ ] `KISS_COLOR`~~ not planned
  - [x] `KISS_DEBUG`
  - [x] `KISS_FORCE`
  - ~~[ ] `KISS_HOOK`~~ not planned
  - [x] `KISS_KEEPLOG`
  - [x] `KISS_PROMPT`
  - [x] `KISS_TMPDIR`
