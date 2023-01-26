package ubirch

import (
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"time"
)

type KeyRegistration struct {
	Algorithm      string `json:"algorithm"`
	Created        string `json:"created"`
	HwDeviceId     string `json:"hwDeviceId"`
	PubKey         string `json:"pubKey"`
	PubKeyId       string `json:"pubKeyId"`
	ValidNotAfter  string `json:"validNotAfter"`
	ValidNotBefore string `json:"validNotBefore"`
}

type SignedKeyRegistration struct {
	PubKeyInfo KeyRegistration `json:"pubKeyInfo"`
	Signature  string          `json:"signature"`
}

func GetSignedKeyRegistration(c Crypto, uid uuid.UUID) ([]byte, error) {
	const timeFormat = "2006-01-02T15:04:05.000Z"

	pubKeyBytes, err := c.GetPublicKeyBytes(uid)
	if err != nil {
		return nil, err
	}

	// put it all together
	now := time.Now().UTC()
	keyRegistration := KeyRegistration{
		Algorithm:      c.AlgorithmId(),
		Created:        now.Format(timeFormat),
		HwDeviceId:     uid.String(),
		PubKey:         base64.StdEncoding.EncodeToString(pubKeyBytes),
		PubKeyId:       base64.StdEncoding.EncodeToString(pubKeyBytes),
		ValidNotAfter:  now.Add(10 * 365 * 24 * time.Hour).Format(timeFormat), // valid for 10 years
		ValidNotBefore: now.Format(timeFormat),
	}

	// create string representation and sign it
	jsonKeyReg, err := json.Marshal(keyRegistration)
	if err != nil {
		return nil, err
	}

	signature, err := c.Sign(uid, jsonKeyReg)
	if err != nil {
		return nil, err
	}

	// fill the certificate
	cert := SignedKeyRegistration{
		PubKeyInfo: keyRegistration,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	return json.Marshal(cert)
}
