# Example recipe

`htop/` is a complete Gemstone recipe for htop, the interactive process viewer. Copy it as a starting point for a new package. It is not part of any repository Gemstone uses.

A recipe is a directory named after the package:

| File | Contents |
|------|----------|
| `version` | `3.5.3 1`: the upstream version, then the release number (raise it when the recipe changes but the upstream version does not) |
| `sources` | one source per line: a URL (archives are extracted with their top directory removed), `git+<url>#<ref>`, or a file in the recipe directory. `%VERSION%` is replaced with the upstream version. An optional second field names the directory to put the source in |
| `checksums` | the SHA-256 of each source, in the same order; `SKIP` for git sources. `gemstone weigh htop` writes it |
| `depends` | one package per line; add `make` after the name for something needed only to build |
| `build` | an executable script, run in the directory that holds the extracted sources as `./build <destdir> <version> <arch>`; it installs into `<destdir>` (`$1`) |
| `meta` | optional `description:`, `url:` and `license:` lines |
| `post-install`, `pre-remove` | optional scripts run on the installed system |
| `patches/`, `files/` | optional local files, listed in `sources` like `patches/fix.patch` |

Try it with a local recipe directory:

```sh
GEMSTONE_PATH=$PWD gemstone forge htop      # build into the package cache
GEMSTONE_PATH=$PWD gemstone mine htop       # build if needed and install
```

The full format is described in Gemstone's README.
