# verifycache

Go package for NVM for Windows **verify cache** (Phases 0–7) and **download cache integrity** (Track 4).

## Role

| Component | Responsibility |
|-----------|----------------|
| `EnsureVerifyKey` | Create or reopen TPM/NCrypt key; export `pubkey.cer` under `{DataRoot}/.verify/` |
| `SignNodeCache` | WinVerifyTrust + AllowedSigners, then TPM-sign canonical payload → HKCU |
| `SignDownloadArchiveCache` | SHA-256 + TPM-sign verified `.7z` archive metadata → HKCU `VerifyCache/download/` |
| `VerifyDownloadArchiveCache` | Re-hash archive, verify stat + TPM signature |
| `PrewarmVerifyCache` | Sign active (and optionally all) installed `node.exe` after reshim |
| `CollectStatus` / `RepairForDoctor` | Doctor reporting and `--autofix` repair |

Shim read path lives in `shim/shared/verifycache.zig` + `wintrust.zig`.

## Layout

```
{DataRoot}/.verify/
  pubkey.cer
  key-container.txt

HKCU\Software\Author Software\Preferences\nvm\VerifyCache\<sha256(node.exe path)>
  Path, Size, Mtime, Thumbprint, Sig, Version=1

HKCU\Software\Author Software\Preferences\nvm\VerifyCache\download\<sha256(archive path)>
  Path, Size, Mtime, Digest, Sig, Version=2
```

Canonical payloads: `v1` (node) and `v2-archive` (`.7z`) in `payload.go`.

## Call sites

- `cli/src/bootstrap/init.go` — `EnsureVerifyKey` (warn-only on TPM failure)
- `cli/src/installer/installer.go` — sign node cache after install; download cache after verified `.7z`
- `cli/src/installer/cache_integrity.go` — verify cached `.7z` on install (TPM, local SHASUM, policy trust, mirror)
- `cli/src/commands/use/version.go` — sign after version switch
- `cli/src/reshim/reshim.go`, `installer/reshim.go` — `PrewarmVerifyCache`
- `sync/src/commands/doctor.go` — status + autofix

## Tests

```powershell
cd common/verifycache
go test ./...
```

Windows only (`//go:build windows`). Fixture export: `export_fixture_test.go`.

## Submodule sync

Implement in `certified/` first, then mirror to community `nvm/` submodules. See `certified/SUBMODULE-SYNC.md`.
