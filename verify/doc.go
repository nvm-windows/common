// Package verify performs layered Authenticode checks for managed executables.
//
// Verification is intentionally two-step:
//
//  1. WinVerifyTrust — OS validates the signature and certificate chain.
//     Stolen or misissued but cryptographically valid certificates pass this step.
//
//  2. AllowedSigners — policy match on the signer organization name from the
//     embedded certificate (O=). The org name is bound to the code-signing cert
//     and cannot be forged without a cert issued to that organization.
//
// AllowedSigners lets administrators restrict vendors (for example OpenJS-only
// vs NodeSource-only builds) after chain validation succeeds.
package verify
