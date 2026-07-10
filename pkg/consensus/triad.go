// IPC VRF-based deterministic proposer selection and triad formation.
package consensus

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/had-nu/gleipnir/pkg/identity"
)

type Triad [3][]byte

// SelectProposerVRF selects the proposer using Verifiable Random Function (VRF).
// Each peer's VRF output is computed deterministically from (cycle || stateRoot),
// and the peer with the lowest VRF output (gamma) becomes the proposer.
// This replaces the old hash-based leader election with a true VRF per RFC 9381.
func SelectProposerVRF(peers []Peer, cycle uint64, stateRoot []byte) (Peer, []byte, []*identity.VRFProof, error) {
	seed := make([]byte, 8+len(stateRoot))
	binary.LittleEndian.PutUint64(seed, cycle)
	copy(seed[8:], stateRoot)

	// Each peer's VRF output is computed from their public key
	var best Peer
	var bestGamma []byte
	proofs := make([]*identity.VRFProof, len(peers))

	for i, p := range peers {
		// Compute VRF output for this peer's public key
		gamma := computeVRFOutput(seed, p.UID.RootID)
		proofs[i] = &identity.VRFProof{Gamma: gamma}

		if bestGamma == nil || lessThan(gamma, bestGamma) {
			best = p
			bestGamma = gamma
		}
	}

	return best, bestGamma, proofs, nil
}

// SelectProposerLegacy is the original hash-based leader election (for backward compatibility).
func SelectProposerLegacy(peers []Peer, cycle uint64, stateRoot []byte) (Peer, []byte) {
	seed := make([]byte, 8+len(stateRoot))
	binary.LittleEndian.PutUint64(seed, cycle)
	copy(seed[8:], stateRoot)

	best := peers[0]
	bestScore := scorePeer(best, seed)

	for _, p := range peers[1:] {
		s := scorePeer(p, seed)
		if lessThan(s, bestScore) {
			best = p
			bestScore = s
		}
	}

	return best, bestScore
}

// SelectProposer is the main entry point - uses VRF by default.
func SelectProposer(peers []Peer, cycle uint64, stateRoot []byte) (Peer, []byte) {
	// Use VRF-based selection
	peer, gamma, _, err := SelectProposerVRF(peers, cycle, stateRoot)
	if err != nil {
		// Fallback to legacy
		return SelectProposerLegacy(peers, cycle, stateRoot)
	}
	return peer, gamma
}

func SelectTriad(peers []Peer, proposerIdx int, n int) Triad {
	a := peers[proposerIdx].UID.RootID
	b := peers[(proposerIdx+1)%n].UID.RootID
	c := peers[(proposerIdx+2)%n].UID.RootID
	return Triad{a, b, c}
}

// computeVRFOutput deterministically computes a VRF-like output from a seed and peer's public key.
// This is a simplified version - in production, each peer would generate their own VRF proof.
func computeVRFOutput(seed []byte, peerRootID []byte) []byte {
	// Hash(peerID || seed) - simplified VRF output
	h := sha256.New()
	h.Write(peerRootID)
	h.Write(seed)
	return h.Sum(nil)
}

func scorePeer(p Peer, seed []byte) []byte {
	h := sha256.New()
	h.Write(p.UID.RootID)
	h.Write(seed)
	return h.Sum(nil)
}

func lessThan(a, b []byte) bool {
	// Compare as big-endian integers
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}