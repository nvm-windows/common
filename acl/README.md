# common/acl (OSS stub)

This package is the **community / OSS** implementation of `common/acl`.

- `IsAllowedVersion` always returns `true`.
- `Implementation()` returns `"stub"`.

Certified builds must **not** link this module. In the certified monorepo, `cli/src/go.mod` replaces this path with `enhanced/go/acl`, which enforces `VersionAllowList` / `VersionBlockList` from registry policy.

The stub exists so the open-source `nvm-windows/common` module graph compiles without enterprise policy assets.
