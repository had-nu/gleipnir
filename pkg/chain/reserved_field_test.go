package chain

import (
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
	if !containsReserved(err.Error()) {
		t.Fatalf("rejected, but not for the stated reason: %v", err)
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

func containsReserved(s string) bool {
	const needle = "reserved"
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
