package ubirch

import "crypto/ecdsa"
import "github.com/paypal/go.crypto/keystore"
import "github.com/google/uuid"

type CryptoContext struct {
	keystore      *keystore.Keystore
	privKey       ecdsa.PrivateKey
	pubKey        ecdsa.PublicKey
	lastSignature []byte
}

func (c *CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	return nil, nil
}
