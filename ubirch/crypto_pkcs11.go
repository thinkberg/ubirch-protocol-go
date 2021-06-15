package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"math/big"
	"time"
)

type ECDSAPKCS11CryptoContext struct {
	pkcs11Ctx        *pkcs11.Ctx          // pkcs11 context for accessing HSM interface
	sessionHandle    pkcs11.SessionHandle // Handle of pkcs11 session
	loginPIN         string               // PIN for logging into the pkcs#11 session
	slotNr           int                  // pkcs#11 slot number to use (zero-based)
	pkcs11Retries    int                  // how often to retry in case of pkcs#11 errors
	pkcs11RetryDelay time.Duration        // how long to pause before retrying after pkcs#11 errors
}

var _ Crypto = (*ECDSAPKCS11CryptoContext)(nil)

// NewECDSAPKCS11CryptoContext initializes the pkcs#11 crypto context including login and session
func NewECDSAPKCS11CryptoContext(pkcs11ctx *pkcs11.Ctx, loginPIN string, slotNr int, pkcs11Retries int, pkcs11RetryDelay time.Duration) (*ECDSAPKCS11CryptoContext, error) {
	E := new(ECDSAPKCS11CryptoContext)
	E.pkcs11Ctx = pkcs11ctx
	E.loginPIN = loginPIN
	E.slotNr = slotNr
	E.pkcs11Retries = pkcs11Retries
	E.pkcs11RetryDelay = pkcs11RetryDelay

	err := E.pkcs11SetupSession()
	if err != nil {
		return nil, err
	}
	return E, nil
}

// Close closes/logs out of the pkcs#11 session and destroys the pkcs#11 context
func (E ECDSAPKCS11CryptoContext) Close() error {

	err := E.pkcs11TeardownSession()
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

	// get the attribute with retries and error handling
	var info []*pkcs11.Attribute
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		info, err = E.pkcs11Ctx.GetAttributeValue(E.sessionHandle, pubKeyHandle, infoTemplate)
		return err
	})
	if retriedErr != nil {
		return nil, retriedErr
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

	pubKeyBytes := info[0].Value[len(expectedHeader):] //save public key, remove DER encoding header

	//check that key point is actually on curve
	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:nistp256XLength])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[nistp256XLength:(nistp256XLength + nistp256YLength)])

	if !pubKey.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("invalid public key value: point not on curve")
	}

	return pubKeyBytes, nil
}

func (E ECDSAPKCS11CryptoContext) SetPublicKey(id uuid.UUID, pubKeyBytes []byte) error {
	panic("implement me")
}

func (E ECDSAPKCS11CryptoContext) PrivateKeyExists(id uuid.UUID) bool {
	objects, err := E.pkcs11GetObjects(id[:], pkcs11.CKO_PRIVATE_KEY, 5)
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

func (E ECDSAPKCS11CryptoContext) PublicKeyExists(id uuid.UUID) (bool, error) {
	objects, err := E.pkcs11GetObjects(id[:], pkcs11.CKO_PUBLIC_KEY, 5)

	if err != nil {
		return true, err
	}
	nrOfKeys := len(objects)
	if nrOfKeys == 1 {
		return true, nil
	} else if nrOfKeys == 0 {
		return false, nil
	} else {
		//something is wrong with the HSM setup
		panic(fmt.Sprintf("found two or more public keys for the UUID '%s', this should never happen", id.String()))
	}
}

func (E ECDSAPKCS11CryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	return fmt.Errorf("implement me")
}

// GenerateKey generates a new keypair using standard templates
func (E ECDSAPKCS11CryptoContext) GenerateKey(id uuid.UUID) error {

	// generate key with retries
	//TODO: add check if there already is a key for this uuid, especially for retries, maybe handle in pkcs11HandleGenericErrors
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, _, err := E.pkcs11Ctx.GenerateKeyPair(E.sessionHandle,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			E.pkcs11PubKeyTemplate(id),
			E.pkcs11PrivKeyTemplate(id),
		)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("failed to generate keypair: %s", retriedErr)
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
	return nistp256SignatureLength
}

func (E ECDSAPKCS11CryptoContext) HashLength() int {
	return sha256Length
}

func (E ECDSAPKCS11CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hash := sha256.Sum256(data)
	return E.SignHash(id, hash[:])
}

func (E ECDSAPKCS11CryptoContext) SignHash(id uuid.UUID, hash []byte) ([]byte, error) {
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}

	keyHandle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}

	var signature []byte
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		err := E.pkcs11Ctx.SignInit(E.sessionHandle, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, keyHandle)
		if err != nil {
			return err
		}

		signature, err = E.pkcs11Ctx.Sign(E.sessionHandle, hash)
		if err != nil {
			return err
		}

		return err
	})
	if retriedErr != nil {
		return nil, retriedErr
	}

	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("SignHash: received invalid signature size: expected %d, got %d", nistp256SignatureLength, len(signature))
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
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:]), // ID should use a consistent identifier across private/public/certs etc.
		// this allows for lookup of all object for a certain device. Here, we use the bytes of the UUID.
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
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:]), // ID should use a consistent identifier across private/public/certs etc.
		// this allows for lookup of all object for a certain device. Here, we use the bytes of the UUID.
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

// gets objects of a certain class with a certain ID (CKA_ID = byte array), which usually is the device UUID bytes, returns up to 'max' objects
func (E ECDSAPKCS11CryptoContext) pkcs11GetObjects(pkcs11id []byte, class uint, max int) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, pkcs11id),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}

	var objects []pkcs11.ObjectHandle
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		err := E.pkcs11Ctx.FindObjectsInit(E.sessionHandle, template)
		if err != nil {
			return err
		}
		objects, _, err = E.pkcs11Ctx.FindObjects(E.sessionHandle, max)
		if err != nil {
			return err
		}

		if err = E.pkcs11Ctx.FindObjectsFinal(E.sessionHandle); err != nil {
			return err
		}
		return err
	})
	if retriedErr != nil {
		return nil, retriedErr
	}

	return objects, nil
}

//pkcs11GetHandle gets the handle to a single object belonging to a certain UUID and of a certain pkcs#11 class,
//errors if zero or more than one object is found
func (E ECDSAPKCS11CryptoContext) pkcs11GetHandle(id uuid.UUID, class uint) (pkcs11.ObjectHandle, error) {
	objects, err := E.pkcs11GetObjects(id[:], class, 2)
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

// pkcs11HandleError tries to handle (and possibly fix) generic pkcs#11 errors like restoring a lost session
// The original error from pkc#11 must be passed in as the argument.
// Returns nil if the error was fixed, or the original error if it is unfixable.
func (E ECDSAPKCS11CryptoContext) pkcs11HandleGenericErrors(pkcs11Error pkcs11.Error) error {
	if pkcs11Error == pkcs11.CKR_OK {
		return nil //exit immediately if there was no error
	}
	//TODO: this is a placeholder, add actual error handling depending on error code
	returnCode := uint(pkcs11Error)
	switch returnCode {
	case pkcs11.CKR_OPERATION_ACTIVE: // some operation was interrupted mid-way: reset session through teardown/setup
		fmt.Println("CKR_OPERATION_ACTIVE: Trying teardown/setup of new session...")
		err := E.pkcs11TeardownSession()
		if err != nil {
			return fmt.Errorf("pkcs11HandleGenericErrors: Error when tearing down session: %s", err)
		}
		err = E.pkcs11SetupSession()
		if err != nil {
			return fmt.Errorf("pkcs11HandleGenericErrors: Error when setting up session: %s", err)
		}
		return nil
	}
	fmt.Printf("Error handler dummy: pkcs#11 return code %d, error message:\n    %s\n", returnCode, pkcs11Error)
	//return pkcs11Error
	fmt.Println("acting as if it was fixed ...")
	return nil
}

//pkcs11Retry is a helper function that retries a pkcs#11 function a defined number of times with an optional sleep delay.
// The passed-in function must return a pkcs11.Error, as its error is passed to pkcs11HandleGenericErrors. Thus this should
// only be used with E.pkcs11Ctx.(...) functions.
// If the function to retry returns more than just an error use an anonymous function inline declaration in the calling
// context to set the variables you need within the scope of the calling function.
func (E ECDSAPKCS11CryptoContext) pkcs11Retry(maxRetries int, sleep time.Duration, f func() error) error {
	for retries := 0; ; retries++ {
		err := f()
		if err == nil { // everything went fine, return
			return nil
		}

		if retries >= maxRetries { // we have tried too often, return
			return fmt.Errorf("pkcs11Retry: gave up after %d retries, last error was: %s", retries, err)
		}

		time.Sleep(sleep) // wait a bit before trying again //TODO: add jitter to avoid 'thundering herd' problems?, pass sleep duration to error handler? (error might not benefit from waiting)

		// call the pkcs11 error handler to try to fix the error before trying again
		err = E.pkcs11HandleGenericErrors(err.(pkcs11.Error))
		if err != nil { // the generic error handler thinks this is an unfixable error, return
			return err
		}

		//try again in next loop...
	}
}

//pkcs11SetupSession sets up a session including initialization and login, uses pkcs11Retry for pkcs11 function calls
func (E *ECDSAPKCS11CryptoContext) pkcs11SetupSession() error {
	//TODO: maybe better to check status of session then do steps as needed

	//initialize
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, E.pkcs11Ctx.Initialize)
	if retriedErr != nil {
		return retriedErr
	}

	// get the slots
	var slots []uint
	var err error
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		slots, err = E.pkcs11Ctx.GetSlotList(true)
		return err
	})
	if retriedErr != nil {
		return retriedErr
	}

	//open a session
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		E.sessionHandle, err = E.pkcs11Ctx.OpenSession(slots[E.slotNr], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		return err
	})
	if retriedErr != nil {
		return retriedErr
	}

	//login
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		err = E.pkcs11Ctx.Login(E.sessionHandle, pkcs11.CKU_USER, E.loginPIN)
		return err
	})
	if retriedErr != nil {
		return retriedErr
	}
	return nil
}

//pkcs11TeardownSession closes and finalizes a session including logout, uses pkcs11Retry for pkcs11 function calls
func (E ECDSAPKCS11CryptoContext) pkcs11TeardownSession() error {
	//TODO: maybe better to check status of session then do steps as needed
	var err error

	//logout
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		err = E.pkcs11Ctx.Logout(E.sessionHandle)
		return err
	})
	if retriedErr != nil {
		return retriedErr
	}

	//close session
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		err = E.pkcs11Ctx.CloseSession(E.sessionHandle)
		return err
	})
	if retriedErr != nil {
		return retriedErr
	}

	//finalize
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, E.pkcs11Ctx.Finalize)
	if retriedErr != nil {
		return retriedErr
	}

	return nil
}
