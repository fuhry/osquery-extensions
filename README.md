# osquery extensions

Exactly as the name suggests, this is a bunch of table extensions for osquery.

## How to build

```
bazel build //cmd/...
```

## How to run

```
bazel run //cmd/NAME -- --socket=/path/to/osquery_extensions.sock
```

## Plugins

### `pacman`

Provides the `pacman_packages` and `pacman_files` tables.

Schema:

```
osquery> .schema pacman_packages
CREATE TABLE pacman_packages(
    `name` TEXT,
    `version` TEXT,
    `description` TEXT,
    `arch` TEXT,
    `url` TEXT,
    `license` TEXT,
    `size` BIGINT,
    `explicit` INTEGER
);

osquery> .schema pacman_files
CREATE TABLE pacman_files(
    `package` TEXT,
    `path` TEXT,
    `size` BIGINT
);
```

### `flatpak`

Provides the `flatpak_packages` table.

Schema:

```
osquery> .schema flatpak_packages
CREATE TABLE flatpak_packages(
    `id` TEXT,
    `type` TEXT,
    `name` TEXT,
    `version` TEXT,
    `hash` TEXT,
    `branch` TEXT,
    `user` TEXT
);
```

## Author/License

Written by Dan Fuhry <dan@fuhry.com>

License: [BSD 3-clause](LICENSE)
