package ubirch

import (
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
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) SetPublicKey(id uuid.UUID, pubKeyBytes []byte) error {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) PrivateKeyExists(id uuid.UUID) bool {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	return fmt.Errorf("Setting private key not implemented for pkcs#11/HSM interfaces")
}

func (E ECDSAPKCS11CryptoContext) GenerateKey(id uuid.UUID) error {
	panic("implement me")
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
func (E ECDSAPKCS11CryptoContext) GetPKCS11Objects(label string, class uint, max int) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}

	if err := E.pkcs11Ctx.FindObjectsInit(E.sessionHandle, template); err != nil {
		return nil, err
	}
	objects, _, err := E.pkcs11Ctx.FindObjects(E.sessionHandle, max)
	if err != nil {
		return nil, fmt.Errorf("failed to find object(s): label %s of class %x, error was %s", label, class, err)
	}

	if err := E.pkcs11Ctx.FindObjectsFinal(E.sessionHandle); err != nil {
		return nil, err
	}

	return objects, nil
}
func (E ECDSAPKCS11CryptoContext) SignHash(id uuid.UUID, hash []byte) ([]byte, error) {
	//TODO: this is unfinished and WIP atm: move finding key out, clean up, use parameters for key label
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}
	objects, err := E.GetPKCS11Objects("myKeyLabel", pkcs11.CKO_PRIVATE_KEY, 2)
	if err != nil {
		return nil, err
	}
	if len(objects) > 1 {
		return nil, fmt.Errorf("Found more than one key")
	} else if len(objects) == 0 {
		return nil, fmt.Errorf("Could not find key")
	}
	keyHandle := objects[0]

	err = E.pkcs11Ctx.SignInit(E.sessionHandle, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, keyHandle)
	if err != nil {
		return nil, err
	}
	signature, err := E.pkcs11Ctx.Sign(E.sessionHandle, hash)
	if err != nil {
		return nil, err
	}
	//TODO: add check for length of returned data
	//if len(signature) !=

	return signature, nil
}

func (E ECDSAPKCS11CryptoContext) Verify(id uuid.UUID, value []byte, signature []byte) (bool, error) {
	panic("implement me")
}
