package ubirch

import (
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
)

type SignedKeyDeletion struct {
	PubKey    string `json:"publicKey"`
	Signature string `json:"signature"`
}

func GetSignedKeyDeletion(c Crypto, uid uuid.UUID) ([]byte, error) {
	pubKeyBytes, err := c.GetPublicKeyBytes(uid)
	if err != nil {
		return nil, err
	}

	signature, err := c.Sign(uid, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	cert := SignedKeyDeletion{
		PubKey:    base64.StdEncoding.EncodeToString(pubKeyBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	return json.Marshal(cert)
}
