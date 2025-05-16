# kiss-ng

Next generation of the [KISS](https://codeberg.org/kiss-community/kiss) package manager, aiming to be more robust and powerful (sandboxed builds, provides system, etc)

# TODO

- [ ] alternatives

- [x] build
  - [ ] run as unprivileged user
  - [ ] sandboxed builds using [`landlock`](https://landlock.io)

- [x] checksum

- [x] download
  - [ ] parallel downloads

- [ ] install
  - [ ] dynamic dependency detector
  - [ ] binary stripping
  - [ ] conflicts

- [x] list

- [x] remove

- [x] search

- [x] update

- [x] upgrade

- [x] hooks (package-specified only, no user hooks)
  - [x] pre-remove
  - [x] post-install

- [ ] provides system

- [ ] global lock for installation/removal

- [ ] environment variables
  - [x] `KISS_ROOT`
  - ~~[ ] `KISS_COMPRESS`~~ `zstd` compression by default
  - [x] `KISS_PATH`
  - [ ] `KISS_COLOR`
  - [x] `KISS_DEBUG`
  - [ ] `KISS_FORCE`
  - ~~[ ] `KISS_HOOK`~~ not planned
  - [ ] `KISS_KEEPLOG`
  - [ ] `KISS_PROMPT`
  - [x] `KISS_TMPDIR`
