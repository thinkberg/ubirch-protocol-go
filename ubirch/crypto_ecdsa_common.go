package ubirch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// EncodePublicKey encodes the Public Key as x509 and returns the encoded PEM
func EncodePublicKey(pub interface{}) ([]byte, error) {
	publicKeyStruct, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type ECDSA public key")
	}
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKeyStruct)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return pemEncoded, nil
}

// DecodePublicKey decodes a Public Key from the x509 PEM format and returns the Public Key
func DecodePublicKey(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

// PublicKeyBytesToStruct converts the public key bytes (x,y) to an ecdsa.PublicKey struct.
func PublicKeyBytesToStruct(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != nistp256PubkeyLength {
		return nil, fmt.Errorf("unexpected length for ECDSA public key: expected %d, got %d", nistp256PubkeyLength, len(pubKeyBytes))
	}

	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[:nistp256XLength])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[nistp256XLength:])

	if !pubKey.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("invalid public key value: point not on curve")
	}

	return pubKey, nil
}

// PublicKeyStructToBytes converts a ecdsa.PublicKey struct to raw bytes
func PublicKeyStructToBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	pubKeyBytes := make([]byte, 0, 0)

	//copy only the bytes available in X/Y.Bytes() while preserving the leading zeroes in paddedX/Y
	//this ensures pubKeyBytes is always the correct size even if X/Y could be represented in
	//less bytes (and thus X/Y.bytes will actually return less bytes)
	paddedX := make([]byte, nistp256XLength)
	paddedY := make([]byte, nistp256YLength)
	copy(paddedX[nistp256XLength-len(pub.X.Bytes()):], pub.X.Bytes())
	copy(paddedY[nistp256YLength-len(pub.Y.Bytes()):], pub.Y.Bytes())
	pubKeyBytes = append(pubKeyBytes, paddedX...)
	pubKeyBytes = append(pubKeyBytes, paddedY...)

	return pubKeyBytes, nil
}

// PublicKeyBytesToPEM converts a ECDSA P-256 public key (64 bytes) to PEM format
func PublicKeyBytesToPEM(pubKeyBytes []byte) (pubkeyPEM []byte, err error) {
	pubKey, err := PublicKeyBytesToStruct(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return EncodePublicKey(pubKey)
}

// PublicKeyPEMToBytes converts a public key from PEM format to raw bytes
func PublicKeyPEMToBytes(pubKeyPEM []byte) ([]byte, error) {
	decodedPubKey, err := DecodePublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decoding public key failed: %v", err)
	}

	return PublicKeyStructToBytes(decodedPubKey)
}

// EncodePrivateKey encodes the Private Key as x509 and returns the encoded PEM
func EncodePrivateKey(priv interface{}) ([]byte, error) {
	privateKeyStruct, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type ECDSA private key")
	}
	x509Encoded, err := x509.MarshalECPrivateKey(privateKeyStruct)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

// DecodePrivateKey decodes a Private Key from the x509 PEM format and returns the Private Key
func DecodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

// PrivateKeyBytesToStruct converts the private key bytes to an ecdsa.PrivateKey struct.
func PrivateKeyBytesToStruct(privKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(privKeyBytes) != nistp256PrivkeyLength {
		return nil, fmt.Errorf("unexpected length for ECDSA private key: expected %d, got %d", nistp256PrivkeyLength, len(privKeyBytes))
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	curveOrder := privKey.PublicKey.Curve.Params().N
	if privKey.D.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid private key value: value is greater or equal curve order")
	}

	return privKey, nil
}

// PrivateKeyBytesToPEM converts a ECDSA P-256 private key (32 bytes) to PEM format
func PrivateKeyBytesToPEM(privKeyBytes []byte) (privKeyPEM []byte, err error) {
	privKey, err := PrivateKeyBytesToStruct(privKeyBytes)
	if err != nil {
		return nil, err
	}

	return EncodePrivateKey(privKey)
}
