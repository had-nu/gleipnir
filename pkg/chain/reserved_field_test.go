package chain

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Um bloco v2 que transporta a chave 8 deve ser rejeitado com
// ErrReservedFieldPresent (3CP §5.3).
//
// A chave 8 (`Sigs` em v1.0) está reservada em ProtocolVersion == 2. O requisito
// não é apenas que Gleipnir nunca a emita — é que a rejeite quando outro emissor a
// traz. São coisas diferentes: um bloco que viola o formato continua a ser um bloco
// que este código não consegue recusar.
//
// Montado a partir de um mapa CBOR genérico, porque `Block` não tem campo para a
// chave 8 (corretamente) e por isso a biblioteca a descarta em silêncio ao
// descodificar — que é precisamente o que este teste mede.
func TestRejectsReservedKey8InV2Block(t *testing.T) {
	// Um bloco v2 válido, codificado pela própria biblioteca.
	valid := Block{
		Index:           1,
		PrevHash:        make([]byte, 32),
		StateRoot:       make([]byte, 32),
		Proposer:        [16]byte{1},
		Lambda1:         1.0,
		Timestamp:       1,
		ProtocolVersion: 2,
		Quorum:          QuorumConfig{TotalValidators: 3, RequiredSigs: 2},
	}
	encoded, err := cbor.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal baseline block: %v", err)
	}

	// Confirma a linha de base: sem a chave 8, o bloco é aceite.
	if _, err := UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("a valid v2 block without key 8 was rejected: %v", err)
	}

	// Reinsere a chave 8 no mapa, preservando o resto.
	withKey8, err := injectKey8(encoded, 8, []any{[]byte{0x01}})
	if err != nil {
		t.Fatalf("inject key 8: %v", err)
	}

	got, err := UnmarshalCBOR(withKey8)
	if err == nil {
		t.Fatalf("a v2 block carrying reserved key 8 was accepted and decoded as "+
			"ProtocolVersion=%d; 3CP §5.3 requires rejection with ErrReservedFieldPresent",
			got.ProtocolVersion)
	}
	if !errors.Is(err, ErrReservedFieldPresent) {
		t.Fatalf("rejected, but not with ErrReservedFieldPresent: %v", err)
	}
}

// injectKey8 re-encodes a canonical CBOR map with one extra key.
func injectKey8(data []byte, key uint64, value any) ([]byte, error) {
	var m map[any]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	m[key] = value
	return cbor.Marshal(m)
}

// The check must not reject blocks the spec accepts.
//
// §5.3 scopes the reservation to "key 8 present and non-null" on a
// ProtocolVersion == 2 block. Each case below is a block the spec requires this decoder
// to accept, and a decoder that refused them would be a different defect: it would break
// v1 blocks, null-valued key 8, and pre-v2 blocks, all of which are legal on the wire.
func TestAcceptsBlocksTheSpecAllows(t *testing.T) {
	base := func(version uint16) Block {
		b := Block{
			Index:           1,
			PrevHash:        make([]byte, 32),
			StateRoot:       make([]byte, 32),
			Proposer:        [16]byte{1},
			Lambda1:         1.0,
			Timestamp:       1,
			ProtocolVersion: version,
			Quorum:          QuorumConfig{TotalValidators: 3, RequiredSigs: 2},
		}
		return b
	}

	t.Run("v2 without key 8", func(t *testing.T) {
		encoded, err := cbor.Marshal(base(2))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := UnmarshalCBOR(encoded); err != nil {
			t.Fatalf("a conformant v2 block was rejected: %v", err)
		}
	})

	t.Run("v1 carrying key 8 is left to v1 semantics", func(t *testing.T) {
		encoded, err := cbor.Marshal(base(1))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		encoded, err = injectKey8(encoded, 8, []any{[]byte{0x01}})
		if err != nil {
			t.Fatalf("inject: %v", err)
		}
		if _, err := UnmarshalCBOR(encoded); err != nil {
			t.Fatalf("§5.3 scopes the reservation to ProtocolVersion 2; "+
				"a v1 block with key 8 must not be rejected here: %v", err)
		}
	})

	t.Run("v2 with key 8 explicitly null", func(t *testing.T) {
		encoded, err := cbor.Marshal(base(2))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		encoded, err = injectRaw(encoded, 8, []byte{0xf6}) // null
		if err != nil {
			t.Fatalf("inject: %v", err)
		}
		if _, err := UnmarshalCBOR(encoded); err != nil {
			t.Fatalf("§5.3 rejects key 8 \"present and non-null\"; "+
				"a null carries no signature field to confuse a v2 reader: %v", err)
		}
	})

	t.Run("unknown non-reserved keys are not rejected", func(t *testing.T) {
		encoded, err := cbor.Marshal(base(2))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		encoded, err = injectRaw(encoded, 200, []byte{0x01})
		if err != nil {
			t.Fatalf("inject: %v", err)
		}
		if _, err := UnmarshalCBOR(encoded); err != nil {
			t.Fatalf("§5.3 reserves key 8 only; rejecting every unknown key would "+
				"refuse extensions the spec has not discussed: %v", err)
		}
	})
}

// injectRaw re-encodes a canonical CBOR map with one extra key holding raw bytes.
func injectRaw(data []byte, key uint64, raw []byte) ([]byte, error) {
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	m[key] = cbor.RawMessage(raw)
	return cbor.Marshal(m)
}
