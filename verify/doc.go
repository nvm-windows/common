// Package verify performs layered Authenticode checks for managed executables.
//
// Verification steps:
//
//  1. WinVerifyTrust — OS validates the signature and certificate chain, with a
//     tiered revocation policy:
//     - Seed paths (install / SignNodeCache / activation): online by default;
//       AirGapped forces cached-only.
//     - Runtime/shim paths: never online (cached or disabled) so warm shim
//       launches stay within a 1–2ms budget (warm verify-cache hits skip this
//       step entirely).
//
//  2. AllowedSigners — policy match on the signer organization name from the
//     embedded certificate (O=).
//
//  3. AllowedThumbprints — optional enterprise pin of exact leaf cert SHA-1
//     thumbprints. Empty list disables pinning.
package verify
