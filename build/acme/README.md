# Bundled acme.sh

`acme.sh` here is the vendored Let's Encrypt / ACME client, embedded into the panel
binary via `//go:embed build/acme/acme.sh` (see main.go) and written out by
`vpn-ui install-acme <path>`.

## Why it is bundled

`obtain_letsencrypt_cert` in `vpn-ui.sh` used to acquire the client at runtime with
`curl https://get.acme.sh | sh`. On a box with no outbound access (or blocked DNS /
firewalled egress to get.acme.sh) that fetch fails, and the deploy printed:

    warning: acme.sh not found after install, skipping real SSL.

silently dropping to plain HTTP. Bundling the client makes real SSL work offline:
the menu extracts this copy and runs its `--install` locally (no network), and only
the final `--issue` reaches out to Let's Encrypt (which needs egress regardless).

## Pinned version

- Upstream: https://github.com/acmesh-official/acme.sh
- Tag: `3.1.4`
- sha256: `fcabf274d4f96966ec933879ae0257266e8ef2f7d16161f14b84dd896c0cac32`

This is the single self-contained `acme.sh` script only (no `dnsapi/`, `deploy/` or
`notify/` plugins): issuance uses the built-in standalone HTTP-01 challenge, which
needs none of them.

## Updating

Fetch the new tag's raw `acme.sh`, drop it in place, and refresh the tag + sha256
above:

    curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/<tag>/acme.sh \
        -o build/acme/acme.sh
    sha256sum build/acme/acme.sh
