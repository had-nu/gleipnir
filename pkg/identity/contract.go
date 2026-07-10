// IPC identity — UID0 derived from a company contract.
// Gleipnir reference implementation.
package identity

import (
	"encoding/hex"
)

// ContractHash computes the canonical hash of a founding/company contract
// document. The resulting digest binds every derived UID0 to the same legal
// root — the "fabric of accountability" across internal services.
func ContractHash(doc []byte) []byte {
	return Hash(doc)
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
			r.buf = Hash(r.buf)
			r.pos = 0
		}
		p[i] = r.buf[r.pos]
		r.pos++
	}
	return len(p), nil
}

// NewUIDZeroFromContract derives a UID0 deterministically from a company
// contract hash. The same (contractHash, nodeSalt) pair always produces the
// same identity — including the Dilithium3 keypair — so a contract member can
// be proven cryptographically without out-of-band key exchange.
//
// nodeSalt distinguishes roles/nodes within the same contract family
// (e.g. "wardex", "anti-ransomware", "founder").
func NewUIDZeroFromContract(contractHash []byte, nodeSalt string, simulated bool) *UIDZeroSoulbound {
	material := append(append([]byte{}, contractHash...), []byte(nodeSalt)...)
	seed := Hash(material) // 32 bytes

	rng := &seedReader{buf: seed}
	pk, sk, err := GenerateDilithiumKey(rng)
	if err != nil {
		pk = make([]byte, 32)
		sk = make([]byte, 32)
	}

	uid := &UIDZeroSoulbound{
		RootID:        seed[:16],
		FEntropy:      seed[16:],
		GenesisHash:   []byte(hex.EncodeToString(seed)),
		CycleIndex:    0,
		GeneratedAt:   generateTimestamp(),
		Simulated:     simulated,
		PublicKey:     pk,
		SecretKey:     sk,
		ContractHash:  contractHash,
	}
	return uid
}

// ContractOf returns the contract hash this UID0 was derived from, or nil if
// it was not contract-derived.
func (u *UIDZeroSoulbound) ContractOf() []byte {
	return u.ContractHash
}
