package identity

import (
	"github.com/cloudflare/circl/kem/schemes"
)

var kyberScheme = schemes.ByName("Kyber1024")

func KyberGenerateKey() (publicKey, secretKey []byte, err error) {
	pk, sk, err := kyberScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkBytes, skBytes, nil
}

func KyberEncapsulate(pkBytes []byte) (ciphertext, sharedSecret []byte, err error) {
	pk, err := kyberScheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := kyberScheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func KyberDecapsulate(skBytes, ct []byte) (sharedSecret []byte, err error) {
	sk, err := kyberScheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	ss, err := kyberScheme.Decapsulate(sk, ct)
	if err != nil {
		return nil, err
	}
	return ss, nil
}
