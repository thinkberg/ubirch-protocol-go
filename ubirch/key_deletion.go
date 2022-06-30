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

func (p *Protocol) GetSignedKeyDeletion(uid uuid.UUID) ([]byte, error) {
	pubKeyBytes, err := p.Crypto.GetPublicKeyBytes(uid)
	if err != nil {
		return nil, err
	}

	signature, err := p.Crypto.Sign(uid, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	cert := SignedKeyDeletion{
		PubKey:    base64.StdEncoding.EncodeToString(pubKeyBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	return json.Marshal(cert)
}
