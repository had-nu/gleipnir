package identity

import (
	"math/big"
	"testing"
)

// groupOrder is l = 2^252 + 27742317777372353535851937790883648493, the order of
// the Ristretto255 prime-order group. Used to build non-canonical scalar
// encodings for the malleability tests.
var groupOrder, _ = new(big.Int).SetString(
	"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

var mod2p256 = new(big.Int).Lsh(big.NewInt(1), 256)

// addGroupOrder returns the encoding of (x + l) mod 2^256, which is a distinct
// byte string that reduces to the same scalar as x.
func addGroupOrder(t *testing.T, x []byte) []byte {
	t.Helper()
	v := new(big.Int).SetBytes(x)
	v.Add(v, groupOrder)
	v.Mod(v, mod2p256)
	out := make([]byte, 32)
	b := v.Bytes()
	copy(out[32-len(b):], b)
	return out
}

func TestVRFProveVerifyRoundTrip(t *testing.T) {
	sk, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("cycle-7||stateroot")

	proof, err := sk.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pk.Verify(alpha, proof)
	if err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("VRF output is %d bytes, want 32", len(out))
	}
}

// The regression this file exists for: Verify previously never read its receiver,
// so a proof made under one key verified against every key in the system.
func TestVRFProofRejectsWrongPublicKey(t *testing.T) {
	victimSK, victimPK, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attackerSK, _, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("leader-selection-input-42")

	proof, err := attackerSK.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := victimPK.Verify(alpha, proof); err == nil {
		t.Fatal("proof made under an attacker's key verified against the victim's public key")
	}

	// Sanity: the same proof does verify against the key that made it.
	if _, err := attackerSK.PublicKey().Verify(alpha, proof); err != nil {
		t.Fatalf("proof rejected under its own key: %v", err)
	}

	// And a victim-made proof does not verify against the attacker's key either.
	own, err := victimSK.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerSK.PublicKey().Verify(alpha, own); err == nil {
		t.Fatal("attacker's key accepted the victim's proof")
	}
}

// Substituting the public key that Y binds to must invalidate the proof: Y is
// part of the challenge, so a different Y yields a different expected challenge.
func TestVRFProofRejectsSubstitutedPublicKey(t *testing.T) {
	skA, _, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pkB, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// pkA must be the key belonging to skA, not an independent keypair.
	pkA := skA.PublicKey()

	alpha := []byte("alpha")
	proof, err := skA.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkA.Verify(alpha, proof); err != nil {
		t.Fatalf("proof rejected under its own key: %v", err)
	}
	if _, err := pkB.Verify(alpha, proof); err == nil {
		t.Fatal("proof verified against a substituted public key")
	}
}

func TestVRFProofRejectsWrongAlpha(t *testing.T) {
	sk, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sk.Prove([]byte("alpha-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Verify([]byte("alpha-2"), proof); err == nil {
		t.Fatal("proof verified for a different alpha")
	}
}

// Non-canonical scalars must be rejected rather than reduced. SetBytes reduces
// modulo l, which would make two byte strings verify for one logical proof.
func TestVRFProofRejectsNonCanonicalScalars(t *testing.T) {
	sk, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("alpha")
	proof, err := sk.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	base := MarshalVRFProof(proof)

	t.Run("challenge", func(t *testing.T) {
		m := append([]byte(nil), base...)
		copy(m[32:64], addGroupOrder(t, m[32:64]))
		got, err := UnmarshalVRFProof(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.Verify(alpha, got); err == nil {
			t.Fatal("C + l accepted as a synonym for C")
		}
	})

	t.Run("response", func(t *testing.T) {
		m := append([]byte(nil), base...)
		copy(m[64:96], addGroupOrder(t, m[64:96]))
		got, err := UnmarshalVRFProof(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.Verify(alpha, got); err == nil {
			t.Fatal("S + l accepted as a synonym for S")
		}
	})
}

func TestVRFVerifyRejectsMalformedProof(t *testing.T) {
	_, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("alpha")

	cases := map[string]*VRFProof{
		"nil":                   nil,
		"empty":                 {},
		"short gamma":           {Gamma: make([]byte, 31), C: make([]byte, 32), S: make([]byte, 32)},
		"short c":               {Gamma: make([]byte, 32), C: make([]byte, 31), S: make([]byte, 32)},
		"short s":               {Gamma: make([]byte, 32), C: make([]byte, 32), S: make([]byte, 31)},
		"zero gamma (identity)": {Gamma: make([]byte, 32), C: make([]byte, 32), S: make([]byte, 32)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := pk.Verify(alpha, p); err == nil {
				t.Fatal("malformed proof accepted")
			}
		})
	}
}

// An identity-element public key would let U = s*B - c*Y and V = s*H - c*Gamma
// collapse to values an attacker chooses, so it is refused at decode time.
func TestVRFPublicKeyFromBytesRejectsIdentity(t *testing.T) {
	if _, err := VRFPublicKeyFromBytes(make([]byte, 32)); err == nil {
		t.Fatal("identity element accepted as a VRF public key")
	}
}

func TestVRFProofIsDeterministic(t *testing.T) {
	sk, _, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("same-input")

	a, err := sk.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sk.Prove(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if string(MarshalVRFProof(a)) != string(MarshalVRFProof(b)) {
		t.Fatal("two proofs for the same (key, alpha) differ")
	}
}

// A decoded proof must not alias the caller's buffer, or reusing or wiping that
// buffer silently rewrites the proof.
func TestUnmarshalVRFProofDoesNotAliasInput(t *testing.T) {
	sk, _, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sk.Prove([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	buf := MarshalVRFProof(proof)
	decoded, err := UnmarshalVRFProof(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 0xFF
	}
	if decoded.Gamma[0] == 0xFF {
		t.Fatal("proof aliases the caller's buffer")
	}
}

func TestUnmarshalVRFProofRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 32, 95, 97, 128} {
		if _, err := UnmarshalVRFProof(make([]byte, n)); err == nil {
			t.Fatalf("%d-byte input accepted", n)
		}
	}
}

// Prove must produce the same output the verifier recomputes, so the VRF output is
// usable without trusting the prover's copy.
func TestVRFOutputMatchesVerifyResult(t *testing.T) {
	sk, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sk.Prove([]byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := pk.Verify([]byte("input"), proof)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(proof.VRFOutput()) {
		t.Fatal("Verify returned an output differing from the proof's Gamma")
	}
}

// Round-tripping through the wire encoding must preserve verifiability.
func TestVRFProofMarshalRoundTrip(t *testing.T) {
	sk, pk, err := GenerateVRFKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sk.Prove([]byte("wire"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalVRFProof(MarshalVRFProof(proof))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Verify([]byte("wire"), decoded); err != nil {
		t.Fatalf("proof from wire encoding rejected: %v", err)
	}
}
