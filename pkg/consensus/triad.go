// IPC VRF-based deterministic proposer selection and triad formation.
package consensus

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/had-nu/gleipnir/pkg/identity"
)

type Triad [3][]byte

var ErrVRFSelectionFailed = errors.New("VRF proposer selection: no valid proofs")

// SelectProposer selects the proposer using VRF. peerProofs maps peer hex ID → VRFProof.
// Each peer computes their own VRF proof locally with their secret key, then gossips it.
// The function verifies every proof against the peer's VRF public key before comparing.
func SelectProposer(peers []Peer, cycle uint64, stateRoot []byte,
	peerProofs map[string]*identity.VRFProof) (Peer, *identity.VRFProof, error) {

	alpha := makeAlpha(cycle, stateRoot)
	return SelectProposerVRF(peers, alpha, peerProofs)
}

// SelectProposerVRF selects the proposer using real ECVRF per RFC 9381.
// peerProofs maps peer hex ID → VRFProof, each computed locally by the peer.
// Every proof is cryptographically verified against the peer's VRF public key.
// The peer with the lowest Gamma (VRF output) is selected.
func SelectProposerVRF(peers []Peer, alpha []byte, peerProofs map[string]*identity.VRFProof) (Peer, *identity.VRFProof, error) {
	if len(peers) == 0 {
		return Peer{}, nil, ErrVRFSelectionFailed
	}

	var best Peer
	var bestProof *identity.VRFProof
	var bestGamma []byte

	for _, p := range peers {
		pid := p.UID.ID()
		proof, ok := peerProofs[pid]
		if !ok || proof == nil {
			continue
		}

		// Verify the proof against this peer's VRF public key
		gamma, err := p.UID.VRFVerifyProof(alpha, proof)
		if err != nil {
			log.Printf("VRF: proof verification failed for peer %s: %v", pid, err)
			continue
		}

		if bestGamma == nil || lessThan(gamma, bestGamma) {
			best = p
			bestProof = proof
			bestGamma = gamma
		}
	}

	if bestGamma == nil {
		return Peer{}, nil, ErrVRFSelectionFailed
	}
	return best, bestProof, nil
}

// makeAlpha constructs the VRF input: (cycle || stateRoot)
func makeAlpha(cycle uint64, stateRoot []byte) []byte {
	alpha := make([]byte, 8+len(stateRoot))
	binary.LittleEndian.PutUint64(alpha, cycle)
	copy(alpha[8:], stateRoot)
	return alpha
}

// SelectTriad selects the triad members (proposer + next 2 peers).
func SelectTriad(peers []Peer, proposerIdx int, n int) Triad {
	a := peers[proposerIdx].UID.RootID
	b := peers[(proposerIdx+1)%n].UID.RootID
	c := peers[(proposerIdx+2)%n].UID.RootID
	return Triad{a, b, c}
}

func lessThan(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
