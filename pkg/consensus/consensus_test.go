package consensus

import (
	"crypto/rand"
	"testing"

	"github.com/had-nu/gleipnir/pkg/identity"
)

func testPeer(id string) Peer {
	uid := identity.NewUIDZero("test-"+id, true)
	return Peer{UID: *uid, Addr: id, Alive: true}
}

func TestSelectProposerDeterministic(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, s1 := SelectProposer(peers, 1, []byte("state1"))
	p2, s2 := SelectProposer(peers, 1, []byte("state1"))

	if p1.Addr != p2.Addr {
		t.Fatalf("same cycle+state should select same proposer: %s vs %s", p1.Addr, p2.Addr)
	}
	if !testEq(s1, s2) {
		t.Fatal("scores should match for same inputs")
	}
}

func TestSelectProposerChangesWithCycle(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _ := SelectProposer(peers, 0, []byte("state"))
	p2, _ := SelectProposer(peers, 1, []byte("state"))

	if p1.Addr == p2.Addr {
		t.Log("same proposer for different cycles is possible but unlikely for 3 peers")
	}
}

func TestSelectProposerChangesWithState(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	p1, _ := SelectProposer(peers, 0, []byte("state-a"))
	p2, _ := SelectProposer(peers, 0, []byte("state-b"))

	if p1.Addr == p2.Addr {
		t.Log("same proposer for different state roots is possible but unlikely for 3 peers")
	}
}

func TestSelectTriad(t *testing.T) {
	peers := []Peer{testPeer("a"), testPeer("b"), testPeer("c")}

	triad := SelectTriad(peers, 0, 3)
	if len(triad) != 3 {
		t.Fatalf("triad should have 3 members, got %d", len(triad))
	}
	if len(triad[0]) == 0 || len(triad[1]) == 0 || len(triad[2]) == 0 {
		t.Fatal("triad members should have non-empty UID slices")
	}
}

func TestVerifyQuorum(t *testing.T) {
	msg := []byte("test block hash")

	var pks [3][]byte
	var sks [3][]byte
	for i := 0; i < 3; i++ {
		pk, sk, err := identity.GenerateDilithiumKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pks[i] = pk
		sks[i] = sk
	}

	var sigs [3][]byte
	for i := 0; i < 3; i++ {
		sigs[i] = identity.SignDilithium(sks[i], msg)
	}

	err := VerifyQuorum(msg, sigs, pks)
	if err != nil {
		t.Fatalf("quorum should pass: %v", err)
	}

	wrongSigs := sigs
	wrongSigs[0] = sigs[1]

	err = VerifyQuorum(msg, wrongSigs, pks)
	if err == nil {
		t.Fatal("quorum should fail with wrong signature")
	}
}

func TestVerifyQuorumWrongKey(t *testing.T) {
	msg := []byte("test")
	_, sk, _ := identity.GenerateDilithiumKey(rand.Reader)
	pk2, _, _ := identity.GenerateDilithiumKey(rand.Reader)

	sig := identity.SignDilithium(sk, msg)

	err := VerifyQuorum(msg, [3][]byte{sig, sig, sig}, [3][]byte{pk2, pk2, pk2})
	if err == nil {
		t.Fatal("quorum should fail with wrong public key")
	}
}

func testEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
