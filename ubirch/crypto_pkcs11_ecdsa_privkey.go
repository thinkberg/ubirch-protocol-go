package ubirch

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"github.com/miekg/pkcs11"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type PKCS11ECDSAPrivKey struct {
	PubKey        *ecdsa.PublicKey     // a pubkey object  matching the private key in the HSM
	PKCS11Ctx     *pkcs11.Ctx          // pkcs11 context for accessing HSM interface
	PrivKeyHandle pkcs11.ObjectHandle  // pkcs11 handle of the private key object to use for signing
	SessionHandle pkcs11.SessionHandle // Handle of the opened and logged-in pkcs11 session
}

func (P *PKCS11ECDSAPrivKey) Public() crypto.PublicKey {
	return P.PubKey
}

func (P *PKCS11ECDSAPrivKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	P.PKCS11Ctx.SignInit(P.SessionHandle, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, P.PrivKeyHandle)
	signature, err = P.PKCS11Ctx.Sign(P.SessionHandle, digest)
	if err != nil {
		return nil, err
	}
	//TODO: How to make sure that the pubkey is in sync with the privkey?
	//TODO: add error check of len(signature) must be two times order of curve basepoint (get it from pubkey),
	// according to pkcs#11 specs '2.3.1 EC Signatures' first half is r, second half s, in total always two times the order
	orderBits := P.PubKey.Curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	fmt.Println("Order (bytes):")
	fmt.Println(orderBytes)
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

var _ crypto.Signer = (*PKCS11ECDSAPrivKey)(nil)
