package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/had-nu/gleipnir/pkg/identity"
)

func cmdInit(validators int, outDir string) error {
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	manifest := make(map[string]string)

	for i := 1; i <= validators; i++ {
		seed := fmt.Sprintf("gleipnir-validator-%d-%s", i, hex.EncodeToString([]byte(fmt.Sprintf("genesis-%d", i))))
		uid := identity.NewUIDZero(seed, true)

		em, err := cbor.Marshal(uid)
		if err != nil {
			return fmt.Errorf("cbor marshal uid-%d: %w", i, err)
		}

		filename := fmt.Sprintf("uid-%d.cbor", i)
		path := filepath.Join(outDir, filename)
		if err := os.WriteFile(path, em, 0600); err != nil {
			return fmt.Errorf("write %s: %w", filename, err)
		}

		manifest[filename] = uid.ID()
		fmt.Printf("Created %s (id=%s)\n", filename, uid.ID())
	}

	fmt.Printf("\nGenesis complete: %d uID0 identities created in %s\n", validators, outDir)
	return nil
}
