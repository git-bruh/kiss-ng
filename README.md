# kiss-ng

Next generation of the [KISS](https://codeberg.org/kiss-community/kiss) package manager, aiming to be more robust and powerful (sandboxed builds, provides system, etc)

# TODO

- [ ] alternatives & choices system

- [ ] provides system

- [x] build
  - [ ] run as unprivileged user
  - [ ] sandboxed builds using [`landlock`](https://landlock.io)

- [x] checksum

- [x] download
  - [ ] parallel downloads

- [x] install
  - [ ] dynamic dependency detector
  - [x] binary stripping
  - [x] conflicts

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
