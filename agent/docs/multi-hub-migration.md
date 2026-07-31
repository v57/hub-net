# Multi-Hub migration and rollback

The multi-Hub release copies released singleton state into one membership. It
does not move or rewrite the legacy files:

- `profile.identity`
- `wireguard.key`
- `publications.json`, when present

Migration publishes `singleton-migrated.json` only after the copied membership
record, private files, and membership index are durable. Repeating migration
is idempotent. Gateway serving is always disabled for migrated memberships,
regardless of prior runtime state; re-enable it explicitly with
`hub-net vpn allow <hubname>`.

## Upgrade

Stop the released singleton service, install the new package, and start it.
Keep `/var/lib/hub-net` intact. Verify the profile and WireGuard key hashes
before and after upgrade:

```sh
sudo sha256sum \
  /var/lib/hub-net/profile.identity \
  /var/lib/hub-net/wireguard.key
```

If startup is interrupted, restart the service. Staged membership recovery is
idempotent and finishes the durable record/index boundary.

## Downgrade

Disable active gateway/full-tunnel state first, stop the service, and install
the prior package. Legacy singleton files remain untouched specifically for
this rollback. The old package ignores the new `memberships/`, `staged/`, and
`singleton-migrated.json` files.

Do not delete the legacy identity or WireGuard key. Confirm their hashes match
the pre-upgrade values before starting the old service.

## Reset

`hub-net removeAll` removes multi-Hub memberships through normal serialized
cleanup. It is not an identity reset.

For an intentional full reset, stop and uninstall the service, move
`/var/lib/hub-net` to a root-only backup, then reinstall. Removing that
directory permanently discards profile identity, WireGuard keys,
publications, memberships, and migration rollback state.
