package main

import "testing"

// TestHexDecodeRejectsMalformedInput covers the two failure modes the previous
// implementation had: an odd-length string indexed past its end, and a non-hex character
// that left the destination byte at zero while reporting success.
//
// hexDecode reads operator-supplied values -- the legacy anchor, snapshot fields -- so a
// typo used to produce a silently wrong genesis rather than an error.
func TestHexDecodeRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain", "00ff11", false},
		{"empty", "", false},
		{"odd length", "0", true},
		{"odd length longer", "00f", true},
		{"non-hex letter", "zz", true},
		{"trailing non-hex", "00fg", true},
		{"wrong separator", "00:ff", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := hexDecode(c.in)
			if c.wantErr && err == nil {
				t.Fatalf("hexDecode(%q) = %v, want an error", c.in, b)
			}
			if !c.wantErr {
				if err != nil {
					t.Fatalf("hexDecode(%q) error = %v", c.in, err)
				}
				if len(b) != len(c.in)/2 {
					t.Fatalf("hexDecode(%q) produced %d bytes, want %d", c.in, len(b), len(c.in)/2)
				}
			}
		})
	}
}

// TestHexDecodeRoundTrip checks the decoder agrees with the encoder.
func TestHexDecodeRoundTrip(t *testing.T) {
	original := []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0xff}
	encoded := hexString(original)
	decoded, err := hexDecode(encoded)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", encoded, err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("got %d bytes, want %d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("byte %d: got %#x, want %#x", i, decoded[i], original[i])
		}
	}
}

// hexString encodes bytes as lower-case hex, matching what an operator would supply.
func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
