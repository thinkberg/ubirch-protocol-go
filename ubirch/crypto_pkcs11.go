package ubirch

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

type ECDSAPKCS11CryptoContext struct {
	pkcs11Ctx     *pkcs11.Ctx          // pkcs11 context for accessing HSM interface
	sessionHandle pkcs11.SessionHandle // Handle of pkcs11 session
	loginPIN      string               // PIN for logging into the pkcs#11 session
	slotNr        int                  // pkcs#11 slot number to use (zero-based)
}

var _ Crypto = (*ECDSAPKCS11CryptoContext)(nil)

// NewECDSAPKCS11CryptoContext initializes the pkcs#11 crypto context including login and session
func NewECDSAPKCS11CryptoContext(pkcs11ctx *pkcs11.Ctx, loginPIN string, slotNr int) (*ECDSAPKCS11CryptoContext, error) {
	E := new(ECDSAPKCS11CryptoContext)
	E.pkcs11Ctx = pkcs11ctx
	E.loginPIN = loginPIN
	E.slotNr = slotNr

	//TODO: maybe better to check status of session then do steps if needed, also move to 'ensureSession()' function or similar
	err := E.pkcs11Ctx.Initialize()
	if err != nil {
		return nil, err
	}

	slots, err := E.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	E.sessionHandle, err = E.pkcs11Ctx.OpenSession(slots[E.slotNr], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}

	err = E.pkcs11Ctx.Login(E.sessionHandle, pkcs11.CKU_USER, loginPIN)
	if err != nil {
		return nil, err
	}

	return E, nil
}

// Close closes/logs out of the pkcs#11 session and destroys the pkcs#11 context
func (E ECDSAPKCS11CryptoContext) Close() error {
	err := E.pkcs11Ctx.Logout(E.sessionHandle)
	if err != nil {
		return err
	}
	err = E.pkcs11Ctx.CloseSession(E.sessionHandle)
	if err != nil {
		return err
	}
	err = E.pkcs11Ctx.Finalize()
	if err != nil {
		return err
	}
	E.pkcs11Ctx.Destroy()
	return nil
}
func (E ECDSAPKCS11CryptoContext) GetPublicKey(id uuid.UUID) ([]byte, error) {
	pubKeyHandle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}

	infoTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil), //we want to get the public key curve point (x,y)
	}
	info, err := E.pkcs11Ctx.GetAttributeValue(E.sessionHandle, pubKeyHandle, infoTemplate)
	if err != nil {
		return nil, err
	}

	if len(info) != 1 {
		return nil, fmt.Errorf("unexpected number of attributes returned from HSM")
	}

	// check the received binary data
	expectedOctetStringLength := nistp256PubkeyLength + 1                 // +1 for the 0x04 'uncompressed' header byte
	expectedHeader := []byte{0x04, byte(expectedOctetStringLength), 0x04} //DER header: 'octet string' + length + 'uncompressed format'
	totalDataLength := len(info[0].Value)
	expectedTotalLength := nistp256PubkeyLength + len(expectedHeader)
	if totalDataLength == 0 {
		return nil, fmt.Errorf("empty public key data returned from HSM")
	} else if totalDataLength != expectedTotalLength {
		return nil, fmt.Errorf("unexpected length of public key data returned from HSM: expected %d, got %d", expectedTotalLength, totalDataLength)
	}
	if !bytes.Equal(info[0].Value[0:len(expectedHeader)], expectedHeader) {
		return nil, fmt.Errorf("unexpected public key data header. expected 0x%x, got 0x%x", expectedHeader, info[0].Value[0:len(expectedHeader)])
	}

	//TODO: maybe add check that point is on curve?

	pubKeyBytes := info[0].Value[len(expectedHeader):] //save public key, remove DER encoding header

	return pubKeyBytes, nil
}

func (E ECDSAPKCS11CryptoContext) SetPublicKey(id uuid.UUID, pubKeyBytes []byte) error {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) PrivateKeyExists(id uuid.UUID) bool {
	objects, err := E.pkcs11GetObjects(id.String(), pkcs11.CKO_PRIVATE_KEY, 5)
	//TODO: how to handle errors if PrivateKeyExists can't return errors?
	// panicking is not a good solution as the problem might be a temporary loss of HSM connection
	if err != nil {
		panic(err)
	}
	nrOfKeys := len(objects)
	if nrOfKeys == 1 {
		return true
	} else if nrOfKeys == 0 {
		return false
	} else {
		//something is wrong with the HSM setup
		panic(fmt.Sprintf("found two or more private keys for the UUID '%s', this should never happen", id.String()))
	}
}

func (E ECDSAPKCS11CryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	return fmt.Errorf("implement me")
}

// GenerateKey generates a new keypair using standard templates
func (E ECDSAPKCS11CryptoContext) GenerateKey(id uuid.UUID) error {
	_, _, err := E.pkcs11Ctx.GenerateKeyPair(E.sessionHandle,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		E.pkcs11PubKeyTemplate(id),
		E.pkcs11PrivKeyTemplate(id),
	)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %s", err)
	}
	return nil
}

func (E ECDSAPKCS11CryptoContext) GetSignedKeyRegistration(uid uuid.UUID, pubKey []byte) ([]byte, error) {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) GetCSR(id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error) {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) SignatureLength() int {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) HashLength() int {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) Sign(id uuid.UUID, value []byte) ([]byte, error) {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) SignHash(id uuid.UUID, hash []byte) ([]byte, error) {
	//TODO: this is unfinished and WIP atm: clean up
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}

	keyHandle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}

	err = E.pkcs11Ctx.SignInit(E.sessionHandle, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, keyHandle)
	if err != nil {
		return nil, err
	}
	signature, err := E.pkcs11Ctx.Sign(E.sessionHandle, hash)
	if err != nil {
		return nil, err
	}

	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("recived invalid signature size: expected %d, got %d", nistp256SignatureLength, len(signature))
	}

	return signature, nil
}

func (E ECDSAPKCS11CryptoContext) Verify(id uuid.UUID, value []byte, signature []byte) (bool, error) {
	panic("implement me")
}

//// PKCS#11 related functions ////

// pkcs11PubKeyTemplate returns the standard public key template, panics if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PubKeyTemplate(id uuid.UUID) []*pkcs11.Attribute {
	if id.String() == "" {
		panic("invalid UUID used for creating public key template")
	}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id.String()), // ID should use a consistent identifier across private/public/certs etc.
		// this allows for lookup of all object for a certain device
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, E.pkcs11PubKeyLabel(id)), // 'description' label of the object

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "secp256r1"),
	}
	return publicKeyTemplate
}

// pkcs11PubKeyLabel returns the label string for CKA_LABEL used to identify pubkeys, panics if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PubKeyLabel(id uuid.UUID) string {
	stringUuid := id.String()
	if stringUuid == "" {
		panic("invalid UUID used for creating public key label")
	}
	return "pub_" + stringUuid
}

// pkcs11PrivKeyTemplate returns the standard private key template, panics if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PrivKeyTemplate(id uuid.UUID) []*pkcs11.Attribute {
	if id.String() == "" {
		panic("invalid UUID used for creating private key template")
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id.String()),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, E.pkcs11PrivKeyLabel(id)),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true), //TODO: add class, maybe also params(?)
		//TODO: check if these attributes make the key not displayable/queryable to user, but exportable in HSM backup
	}
	return privateKeyTemplate
}

// pkcs11PrivKeyLabel returns the label string for CKA_LABEL used to identify private keys, panics if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PrivKeyLabel(id uuid.UUID) string {
	stringUuid := id.String()
	if stringUuid == "" {
		panic("invalid UUID used for creating private key label")
	}
	return "priv_" + stringUuid
}

// gets objects of a certain class with a certain ID (CKA_ID), which usually is the device UUID, returns up to 'max' objects
func (E ECDSAPKCS11CryptoContext) pkcs11GetObjects(pkcs11id string, class uint, max int) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, pkcs11id),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}

	if err := E.pkcs11Ctx.FindObjectsInit(E.sessionHandle, template); err != nil {
		return nil, err
	}
	objects, _, err := E.pkcs11Ctx.FindObjects(E.sessionHandle, max)
	if err != nil {
		return nil, fmt.Errorf("failed to find object(s): id %s of class %x, error was %s", pkcs11id, class, err)
	}

	if err := E.pkcs11Ctx.FindObjectsFinal(E.sessionHandle); err != nil {
		return nil, err
	}

	return objects, nil
}

//pkcs11GetHandle gets the handle to a single object belonging to a certain UUID and of a certain pkcs#11 class,
//errors if zero or more than one object is found
func (E ECDSAPKCS11CryptoContext) pkcs11GetHandle(id uuid.UUID, class uint) (pkcs11.ObjectHandle, error) {
	objects, err := E.pkcs11GetObjects(id.String(), class, 2)
	if err != nil {
		return 0, err
	}
	if len(objects) > 1 {
		return 0, fmt.Errorf("found more than one object")
	} else if len(objects) == 0 {
		return 0, fmt.Errorf("could not find object")
	}
	return objects[0], nil
}
