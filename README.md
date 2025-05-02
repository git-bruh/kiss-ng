# kiss-ng

Next generation of the [KISS](https://codeberg.org/kiss-community/kiss) package manager, aiming to be more robust and powerful (sandboxed builds, provides system, etc)

# TODO

- [ ] alternatives

- [ ] build
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

- [ ] remove

- [x] search

- [x] update

- [x] upgrade

- [ ] hooks

- [ ] provides system

- [ ] environment variables
  - [x] `KISS_ROOT`
  - [ ] `KISS_COMPRESS`
  - [x] `KISS_PATH`
  - [ ] `KISS_COLOR`
  - [ ] `KISS_DEBUG`
  - [ ] `KISS_FORCE`
  - [ ] `KISS_HOOK`
  - [ ] `KISS_KEEPLOG`
  - [ ] `KISS_PROMPT`
  - [ ] `KISS_TMPDIR`
