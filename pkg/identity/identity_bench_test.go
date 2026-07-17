//nolint:errcheck // benchmark assertions
package identity

import (
	"crypto/rand"
	"testing"
)

func BenchmarkDilithium3Keygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateDilithiumKey(rand.Reader)
	}
}

func BenchmarkDilithium3Sign(b *testing.B) {
	_, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for signing 32 bytes!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignDilithium(sk, msg)
	}
}

func BenchmarkDilithium3Verify(b *testing.B) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for verifying")
	sig := SignDilithium(sk, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyDilithium(pk, msg, sig)
	}
}

func BenchmarkBlake3Hash(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkSignAndVerifyCombined(b *testing.B) {
	pk, sk, err := GenerateDilithiumKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig := SignDilithium(sk, msg)
		VerifyDilithium(pk, msg, sig)
	}
}
