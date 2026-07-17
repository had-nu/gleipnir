//nolint:errcheck // benchmark assertions
package consensus

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/had-nu/gleipnir/pkg/chain"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func BenchmarkSelectProposer(b *testing.B) {
	sizes := []int{3, 10, 50}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("peers=%d", n), func(b *testing.B) {
			peers := make([]Peer, n)
			for i := 0; i < n; i++ {
				uid := identity.NewUIDZero(fmt.Sprintf("peer-%d", i), true)
				peers[i] = Peer{UID: *uid, Addr: fmt.Sprintf("addr-%d", i), Alive: true}
			}
			state := []byte("test-state-root")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				proofs := vrfProofsForPeers(peers, uint64(i), state)
				SelectProposer(peers, uint64(i), state, proofs)
			}
		})
	}
}

func BenchmarkSelectTriad(b *testing.B) {
	peers := make([]Peer, 10)
	for i := 0; i < 10; i++ {
		uid := identity.NewUIDZero(fmt.Sprintf("peer-%d", i), true)
		peers[i] = Peer{UID: *uid, Addr: fmt.Sprintf("addr-%d", i), Alive: true}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SelectTriad(peers, i%10, 3)
	}
}

func BenchmarkVerifyQuorum(b *testing.B) {
	msg := []byte("benchmark block hash for quorum verification")
	pks := make([][]byte, 3)
	sks := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		pk, sk, err := identity.GenerateDilithiumKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		pks[i] = pk
		sks[i] = sk
	}
	sigs := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		sigs[i] = identity.SignDilithium(sks[i], msg)
	}
	quorum := chain.DefaultQuorumConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyQuorum(msg, sigs, pks, quorum)
	}
}
