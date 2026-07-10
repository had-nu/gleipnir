package validation

import (
	"testing"
)

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		name        string
		hash        [32]byte
		submitter   []byte
		label       string
		limits      APILimits
		wantErrCode string
	}{
		{
			name:        "valid entry",
			hash:        [32]byte{1},
			submitter:   []byte("submitter"),
			label:       "test",
			limits:      DefaultAPILimits(),
			wantErrCode: "",
		},
		{
			name:        "zero hash rejected",
			hash:        [32]byte{},
			submitter:   []byte("submitter"),
			label:       "test",
			limits:      DefaultAPILimits(),
			wantErrCode: ErrCodeInvalidHash,
		},
		{
			name:        "empty submitter rejected",
			hash:        [32]byte{1},
			submitter:   []byte{},
			label:       "test",
			limits:      DefaultAPILimits(),
			wantErrCode: ErrCodeInvalidSubmitter,
		},
		{
			name:        "label too long rejected",
			hash:        [32]byte{1},
			submitter:   []byte("submitter"),
			label:       string(make([]byte, 300)),
			limits:      DefaultAPILimits(),
			wantErrCode: ErrCodeLabelTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEntry(tt.hash, tt.submitter, tt.label, tt.limits)
			if tt.wantErrCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				code, ok := FromError(err)
				if !ok {
					t.Fatalf("error not a ValidationError: %v", err)
				}
				if code != tt.wantErrCode {
					t.Fatalf("expected code %s, got %s", tt.wantErrCode, code)
				}
			}
		})
	}
}

func TestIsZeroHash(t *testing.T) {
	if !IsZeroHash([32]byte{}) {
		t.Fatal("zero hash should return true")
	}
	if IsZeroHash([32]byte{1}) {
		t.Fatal("non-zero hash should return false")
	}
}

func TestDefaultAPILimits(t *testing.T) {
	limits := DefaultAPILimits()
	if limits.MaxLabelLen != 256 {
		t.Fatalf("expected MaxLabelLen=256, got %d", limits.MaxLabelLen)
	}
	if limits.MaxTotalPending != 100000 {
		t.Fatalf("expected MaxTotalPending=100000, got %d", limits.MaxTotalPending)
	}
	if limits.MaxPendingPerSubmitter != 5000 {
		t.Fatalf("expected MaxPendingPerSubmitter=5000, got %d", limits.MaxPendingPerSubmitter)
	}
}