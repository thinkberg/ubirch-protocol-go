package ubirch

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type ECDSAPKCS11PrivKey struct {
	pkcs11Crypto *ECDSAPKCS11CryptoContext // pkcs11 crypto context that is used for accessing the HSM
	id           uuid.UUID                 // UUID of the keypair
	pubKey       *ecdsa.PublicKey          // a pubkey object  matching the private key in the HSM, auto-generated on creation
}

var _ crypto.Signer = (*ECDSAPKCS11PrivKey)(nil)

// newPKCS11ECDSAPrivKey creates a private key struct which can be used for signing (implements crypto.signer) even
// though the private key is in a HSM. It uses The SHA-256 digest signing function SignHash() of the passed in pkcs11
// crypto context.
func newPKCS11ECDSAPrivKey(id uuid.UUID, ctx *ECDSAPKCS11CryptoContext) (*ECDSAPKCS11PrivKey, error) {
	P := new(ECDSAPKCS11PrivKey)
	P.id = id
	P.pkcs11Crypto = ctx

	//check for existence of keypair
	privExists := P.pkcs11Crypto.PrivateKeyExists(id)
	if !privExists {
		return nil, fmt.Errorf("newPKCS11ECDSAPrivKey: no private key in HSM")
	}

	pubExists, err := P.pkcs11Crypto.PublicKeyExists(id)
	if err != nil {
		return nil, fmt.Errorf("newPKCS11ECDSAPrivKey: can't check for public key: %s", err)
	}
	if !pubExists {
		return nil, fmt.Errorf("newPKCS11ECDSAPrivKey: no public key in HSM")
	}

	//get public key bytes
	pubKeyBytes, err := P.pkcs11Crypto.GetPublicKey(id)
	if err != nil {
		return nil, fmt.Errorf("newPKCS11ECDSAPrivKey: getting pubkey failed: %s", err)
	}
	if len(pubKeyBytes) != nistp256PubkeyLength {
		return nil, fmt.Errorf("newPKCS11ECDSAPrivKey: received invalid public key length: expected %d, got %d bytes", nistp256PubkeyLength, len(pubKeyBytes))
	}

	//create the key object
	P.pubKey = new(ecdsa.PublicKey)
	P.pubKey.Curve = elliptic.P256()
	P.pubKey.X = &big.Int{}
	P.pubKey.X.SetBytes(pubKeyBytes[0:nistp256XLength])
	P.pubKey.Y = &big.Int{}
	P.pubKey.Y.SetBytes(pubKeyBytes[nistp256XLength:(nistp256XLength + nistp256YLength)])

	if !P.pubKey.IsOnCurve(P.pubKey.X, P.pubKey.Y) {
		return nil, fmt.Errorf("invalid public key value: point not on curve")
	}

	return P, nil
}

func (P *ECDSAPKCS11PrivKey) Public() crypto.PublicKey {
	return P.pubKey
}

func (P *ECDSAPKCS11PrivKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("ECDSAPKCS11PrivKey: pkcs11Crypto.SignHash() can only sign SHA256 digests")
	}
	signatureBytes, err := P.pkcs11Crypto.SignHash(P.id, digest)
	if err != nil {
		return nil, err
	}

	//TODO: How to make sure that the pubkey is in sync with the privkey?

	// check of len(signatureBytes): must be two times order of curve basepoint (which we get from the pubkey),
	// according to pkcs#11 specs '2.3.1 EC Signatures' first half is r, second half s
	orderBits := P.pubKey.Curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(signatureBytes) != 2*orderBytes {
		return nil, fmt.Errorf("received signature size is not 2*curve order size, expected %d bytes, got %d", 2*orderBytes, len(signatureBytes))
	}
	rsSize := orderBytes // size of r and s is the same as order size
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(signatureBytes[:rsSize])
	s.SetBytes(signatureBytes[rsSize:])

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}
