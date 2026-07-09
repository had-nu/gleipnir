package consensus

import (
	"crypto/sha256"
	"encoding/binary"
)

type Triad [3][]byte

func SelectProposer(peers []Peer, cycle uint64, stateRoot []byte) (Peer, []byte) {
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

func SelectTriad(peers []Peer, proposerIdx int, n int) Triad {
	a := peers[proposerIdx].UID.RootID
	b := peers[(proposerIdx+1)%n].UID.RootID
	c := peers[(proposerIdx+2)%n].UID.RootID
	return Triad{a, b, c}
}

func scorePeer(p Peer, seed []byte) []byte {
	h := sha256.Sum256(append(p.UID.RootID, seed...))
	return h[:]
}

func lessThan(a, b []byte) bool {
	return string(a) < string(b)
}
