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

### `x509_certificates`

Provides the `x509_certificates` table.

Queries against this table must include a `WHERE path = 'absolute path'` constraint.

This table will discover multiple certificates in a single file, distinguished by the `index` column.

Schema:

```
osquery> .schema x509_certificates
CREATE TABLE x509_certificates(
    `path` TEXT,                   -- Absolute path of the certificate file
    `index` INT,                   -- Indicates the certificate's position in the file
    `error` TEXT,                  -- Set to non-empty string if there was an error parsing the certificate
    `encoding` TEXT,               -- "DER" or "PEM"
    `subject` TEXT,                -- X.500 string-encoded subject name
    `issuer` TEXT,                 -- X.500 string-encoded issuer name
    `serial` TEXT,                 -- Hex-encoded serial number of the certificate
    `is_ca` INTEGER,               -- Set to "1" if the certificate has the "CA" flag set, "0" otherwise
    `public_key` TEXT,             -- PKCS#8-encoded public key of the certificate
    `public_key_algorithm` TEXT,   -- "RSA" and "ECDSA" are currently supported; empty string otherwise
    `public_key_size` INTEGER,     -- Normalized length of the public key, in bits
    `alt_names` TEXT,              -- Comma-separated list of subject alternative names. Each will have one of the following prefixes: "DNS:", "MAIL:", "IP:" or "URI:". Order is not guaranteed.
    `not_before` BIGINT,           -- Seconds since epoch of when the certificate becomes valid
    `not_after` BIGINT,            -- Seconds since epoch of when the certificate expires
    `remaining_ttl` INTEGER,       -- Seconds until the certificate expires. Set to 0 if the certificate is expired or not valid yet.
    `remaining_pct` INTEGER,       -- Percentage of time remaining in the certificate's validity period. Set to 0 if the certificate is expired or not valid yet.
    `valid_now` INTEGER,           -- Set to 1 if the current time is between the certificate's NotBefore and NotAfter timestamps; 0 otherwise.
    `sha1_thumbprint` TEXT,        -- Hex-encoded SHA-1 digest of the certificate's DER-encoded form.
    `sha256_thumbprint` TEXT,      -- Hex-encoded SHA-256 digest of the certificate's DER-encoded form.
);
```

## Author/License

Written by Dan Fuhry <dan@fuhry.com>

License: [BSD 3-clause](LICENSE)
