// IPC identity — UID0 v2.0 derived from a company contract.
// Gleipnir reference implementation of 3CP v2.0.
package identity

import (
	"encoding/hex"
)

// ContractHash computes the canonical hash of a founding/company contract
// document. The resulting digest binds every derived UID0 to the same legal
// root — the "fabric of accountability" across internal services.
func ContractHash(doc []byte) [32]byte {
	return Blake3Hash(doc)
}

// DRBG seeded from a fixed seed. Implements io.Reader so it can drive
// GenerateDilithiumKey deterministically for contract-derived identities.
type seedReader struct {
	buf []byte
	pos int
}

func (r *seedReader) Read(p []byte) (int, error) {
	for i := range p {
		if r.pos >= len(r.buf) {
			r.buf = Hash(r.buf)[:]
			r.pos = 0
		}
		p[i] = r.buf[r.pos]
		r.pos++
	}
	return len(p), nil
}

// NewUIDZeroFromContract derives a UID0 v2.0 deterministically from a company
// contract hash. The same (contractHash, nodeSalt) pair always produces the
// same identity — including the Dilithium3 keypair — so a contract member can
// be proven cryptographically without out-of-band key exchange.
//
// nodeSalt distinguishes roles/nodes within the same contract family
// (e.g. "wardex", "anti-ransomware", "founder").
func NewUIDZeroFromContract(contractHash [32]byte, nodeSalt string, simulated bool) (*UIDZeroSoulbound, error) {
	// Use contractHash + nodeSalt as entropy source for NewUIDZero
	material := append(contractHash[:], []byte(nodeSalt)...)
	entropySource := hex.EncodeToString(material)

	// Create a NetworkID from contractHash for HKDF derivation
	// In practice, NetworkID comes from genesis block, but for contract-derived
	// identities we use the contract hash as the network identifier
	var networkID [32]byte
	copy(networkID[:], contractHash[:])

	return NewUIDZero(entropySource, networkID, simulated, contractHash)
}

// ContractOf returns the contract hash this UID0 was derived from.
func (u *UIDZeroSoulbound) ContractOf() [32]byte {
	return u.ContractHash
}