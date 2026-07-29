package identity

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// CanonicalPayload creates a deterministic payload for signing/verification
// Format: Hash || Submitter || Timestamp (LE64) || Label
func CanonicalPayload(hash []byte, submitter []byte, timestamp int64, label string) []byte {
	buf := make([]byte, 0, len(hash)+len(submitter)+8+len(label))
	buf = append(buf, hash...)
	buf = append(buf, submitter...)

	tsBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBuf, uint64(timestamp))
	buf = append(buf, tsBuf...)
	buf = append(buf, []byte(label)...)

	return buf
}

// VerifySignature verifies a Dilithium3 signature against a canonical payload
func VerifySignature(pubKey []byte, hash []byte, submitter []byte, timestamp int64, label string, signature []byte) bool {
	payload := CanonicalPayload(hash, submitter, timestamp, label)
	return VerifyDilithium3(pubKey, payload, signature)
}

// SignPayload creates a Dilithium3 signature for a canonical payload
func SignPayload(secretKey []byte, hash []byte, submitter []byte, timestamp int64, label string) []byte {
	payload := CanonicalPayload(hash, submitter, timestamp, label)
	return SignDilithium(secretKey, payload)
}

// VerifyDilithium3 verifies a Dilithium3 signature
func VerifyDilithium3(pubKey []byte, payload []byte, signature []byte) bool {
	pk := &mode3.PublicKey{}
	if err := pk.UnmarshalBinary(pubKey); err != nil {
		return false
	}
	return mode3.Verify(pk, payload, signature)
}

// SignDilithium3 signs a payload with Dilithium3
func SignDilithium3(secretKey []byte, payload []byte) []byte {
	sk := &mode3.PrivateKey{}
	if err := sk.UnmarshalBinary(secretKey); err != nil {
		return nil
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, payload, sig)
	return sig
}

// PublicKeyHex returns hex encoding of a public key
func PublicKeyHex(pubKey []byte) string {
	return hex.EncodeToString(pubKey)
}

// ParsePublicKeyHex parses a hex-encoded public key
func ParsePublicKeyHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}