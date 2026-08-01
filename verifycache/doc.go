// Package verifycache provisions TPM-backed signing keys and stores verify-cache
// metadata under {DataRoot}/.verify for runtime node.exe trust acceleration.
//
// Phase 2 creates the user-scoped NCrypt key and exports the public half to
// pubkey.cer. Phase 3 adds HKCU cache writes and TPM signatures.
package verifycache
