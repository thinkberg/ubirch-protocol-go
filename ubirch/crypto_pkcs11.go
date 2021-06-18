package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

// GetPublicKey gets the binary public key data as returned by the HSM
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

func (E ECDSAPKCS11CryptoContext) SetPublicKey(uuid.UUID, []byte) error {
	return fmt.Errorf("SetPublicKey() not sensible on HSMs, please use SetKey() with a private key to set a keypair")
}

func (E ECDSAPKCS11CryptoContext) PrivateKeyExists(id uuid.UUID) (bool, error) {
	objects, err := E.pkcs11GetObjects(id[:], pkcs11.CKO_PRIVATE_KEY, 5)
	if err != nil {
		return true, fmt.Errorf("getting object failed: %s", err) //safer to assume there is a key in case of error
	}
	nrOfKeys := len(objects)
	if nrOfKeys == 1 {
		return true, nil
	} else if nrOfKeys == 0 {
		return false, nil
	} else {
		//something is wrong with the HSM setup
		return true, fmt.Errorf("found two or more private keys for the UUID '%s', this should never happen", id.String())
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
		return true, fmt.Errorf("found two or more public keys for the UUID '%s', this should never happen", id.String())
	}
}

// SetKey takes a private key (32 bytes), calculates the public key and sets both private and public key in the HSM
// SetKey will fail if a private or public key for this UUID already exists, as else it would overwrite HSM keys.
func (E ECDSAPKCS11CryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	if len(privKeyBytes) != nistp256PrivkeyLength {
		return fmt.Errorf("unexpected length for ECDSA private key: expected %d, got %d", nistp256PrivkeyLength, len(privKeyBytes))
	}
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}
	// check for existing keys
	privExists, err := E.PrivateKeyExists(id)
	if err != nil {
		return fmt.Errorf("SetKey: checking for private key existence failed: %s", err)
	}
	if privExists {
		return fmt.Errorf("SetKey: private key already exists")
	}
	pubExists, err := E.PublicKeyExists(id)
	if err != nil {
		return fmt.Errorf("SetKey: checking public key existence failed: %s", err)
	}
	if pubExists {
		return fmt.Errorf("SetKey: public key already exists")
	}

	// create private key object for calculation of public key and do calculation
	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	curveOrder := privKey.PublicKey.Curve.Params().N
	if privKey.D.Cmp(curveOrder) >= 0 {
		return fmt.Errorf("SetKey: invalid private key value: value is greater or equal curve order")
	}

	//create keypair templates and add key data and DER header  //TODO: check for more efficient way of concatenating
	var bytesX [nistp256XLength]byte
	var bytesY [nistp256XLength]byte
	privKey.PublicKey.X.FillBytes(bytesX[:])
	privKey.PublicKey.Y.FillBytes(bytesY[:])
	pubKeyBytesHSM := []byte{0x04, nistp256PubkeyLength + 1, 0x04} // header = 0x04 'octet string' + length + 0x04 'uncompressed public key'
	pubKeyBytesHSM = append(pubKeyBytesHSM, bytesX[:]...)          // append X
	pubKeyBytesHSM = append(pubKeyBytesHSM, bytesY[:]...)          // append Y

	pubKeyTemplate, err := E.pkcs11PubKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("SetKey: could not get public key template: %s", err)
	}
	pubKeyTemplate = append(pubKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pubKeyBytesHSM)) // add the DER-encoding of ANSI X9.62 ECPoint value Q

	var privKeyBytesHSM [nistp256PrivkeyLength]byte
	privKey.D.FillBytes(privKeyBytesHSM[:])
	privKeyTemplate, err := E.pkcs11PrivKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("SetKey: could not get private key template: %s", err)
	}
	privKeyTemplate = append(privKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKeyBytesHSM[:])) // add the X9.62 private value d
	privKeyTemplate = append(privKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "secp256r1"))    // normally derived from public key, but must be explicit here

	//write keys to HSM
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, err := E.pkcs11Ctx.CreateObject(E.sessionHandle, pubKeyTemplate)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("SetKey: failed to set public key: %s", retriedErr)
	}
	retriedErr = E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, err := E.pkcs11Ctx.CreateObject(E.sessionHandle, privKeyTemplate)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("SetKey: failed to set private key: %s", retriedErr)
	}

	return nil
}

// GenerateKey generates a new keypair using standard templates
func (E ECDSAPKCS11CryptoContext) GenerateKey(id uuid.UUID) error {

	// check for existing keys
	privExists, err := E.PrivateKeyExists(id)
	if err != nil {
		return fmt.Errorf("GenerateKey: checking private key existence failed: %s", err)
	}
	if privExists {
		return fmt.Errorf("GenerateKey: private key already exists")
	}
	pubExists, err := E.PublicKeyExists(id)
	if err != nil {
		return fmt.Errorf("GenerateKey: checking public key existence failed: %s", err)
	}
	if pubExists {
		return fmt.Errorf("GenerateKey: public key already exists")
	}

	// get key templates
	pubKeyTemplate, err := E.pkcs11PubKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("GenerateKey: can't get public key template: %s", err)
	}
	privKeyTemplate, err := E.pkcs11PrivKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("GenerateKey: can't get private key template: %s", err)
	}
	// generate key with retries
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, _, err := E.pkcs11Ctx.GenerateKeyPair(E.sessionHandle,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			pubKeyTemplate,
			privKeyTemplate,
		)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("failed to generate keypair: %s", retriedErr)
	}

	return nil
}

//GetSignedKeyRegistration is not implemented.
func (E ECDSAPKCS11CryptoContext) GetSignedKeyRegistration(uuid.UUID, []byte) ([]byte, error) {
	return nil, fmt.Errorf("GetSignedKeyRegistration not implemented") //TODO: check why this function is in the interface, it's not in crypto.go
}

// GetCSR gets a certificate signing request.
func (E ECDSAPKCS11CryptoContext) GetCSR(id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error) {
	hsmPrivateKey, err := newPKCS11ECDSAPrivKey(id, &E)
	if err != nil {
		return nil, err
	}

	//create CSR template
	csrTemplate := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			Country:      []string{subjectCountry},
			Organization: []string{subjectOrganization},
			CommonName:   id.String(),
		},
	}

	//sign it using SignHash() of the pkcs11 crypto context (via the hsmPrivateKey/PKCS11ECDSAPrivKey)
	csr, err := x509.CreateCertificateRequest(nil, csrTemplate, hsmPrivateKey) //we don't need a rand reader as this is provided by the HSM internally
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func (E ECDSAPKCS11CryptoContext) SignatureLength() int {
	return nistp256SignatureLength
}

func (E ECDSAPKCS11CryptoContext) HashLength() int {
	return sha256Length
}

// Sign creates the signature for arbitrary data using the private key of the given UUID
func (E ECDSAPKCS11CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hash := sha256.Sum256(data)
	return E.SignHash(id, hash[:])
}

// SignHash retrieves the signature for an already computed SHA-256 hash using the private key of the given UUID from the HSM.
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

// Verify verifies that 'signature' matches 'data' using the public key with a specific UUID.
// It retrieves the public key for the UUID  from the HSM and then verifies the signature locally (using ecdsa.Verify())
// Returns 'true' and 'nil' error if signature was verifiable.
func (E ECDSAPKCS11CryptoContext) Verify(id uuid.UUID, data []byte, signature []byte) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("empty data cannot be verified")
	}
	if len(signature) != nistp256SignatureLength {
		return false, fmt.Errorf("wrong signature length: expected: %d, got: %d", nistp256SignatureLength, len(signature))
	}

	//get public key bytes from HSM
	pubkeyBytes, err := E.GetPublicKey(id)
	if err != nil {
		return false, fmt.Errorf("Verify: could not get public key bytes from HSM: %s", err)
	}

	// convert bytes to pubkey struct
	pub, err := E.pkcs11BytesToPublicKeyStruct(pubkeyBytes)
	if err != nil {
		return false, err
	}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:nistp256RLength])
	s.SetBytes(signature[nistp256SLength:])

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s), nil
}

//// PKCS#11 related functions ////

// pkcs11PubKeyTemplate returns the standard public key template, errors if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PubKeyTemplate(id uuid.UUID) ([]*pkcs11.Attribute, error) {
	if id.String() == "" {
		return nil, fmt.Errorf("invalid UUID used for creating public key template")
	}
	pubkeyLabel, err := E.pkcs11PubKeyLabel(id)
	if err != nil {
		return nil, fmt.Errorf("pkcs11PubKeyTemplate: can't get label: %s", err)
	}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:]), // ID should use a consistent identifier across private/public/certs etc.
		// this allows for lookup of all object for a certain device. Here, we use the bytes of the UUID.
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubkeyLabel), // 'description' label of the object

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "secp256r1"),
	}
	return publicKeyTemplate, nil
}

// pkcs11PubKeyLabel returns the label string for CKA_LABEL used to identify pubkeys, errors if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PubKeyLabel(id uuid.UUID) (string, error) {
	stringUuid := id.String()
	if stringUuid == "" {
		return "invalid_UUID", fmt.Errorf("invalid UUID used for creating public key label")
	}
	return stringUuid + "_pub", nil
}

// pkcs11PrivKeyTemplate returns the standard private key template, errors if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PrivKeyTemplate(id uuid.UUID) ([]*pkcs11.Attribute, error) {
	if id.String() == "" {
		return nil, fmt.Errorf("invalid UUID used for creating private key template")
	}
	privkeyLabel, err := E.pkcs11PrivKeyLabel(id)
	if err != nil {
		return nil, fmt.Errorf("pkcs11PrivKeyTemplate: can't get label: %s", err)
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:]), // ID should use a consistent identifier across private/public/certs etc.
		// this allows for lookup of all object for a certain device. Here, we use the bytes of the UUID.
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privkeyLabel),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		//pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "secp256r1"), //not needed as params are derived from public key
		//TODO: check if these attributes make the key not displayable/queryable to user, but exportable in HSM backup
	}
	return privateKeyTemplate, nil
}

// pkcs11PrivKeyLabel returns the label string for CKA_LABEL used to identify private keys, errors if UUID is invalid
func (E ECDSAPKCS11CryptoContext) pkcs11PrivKeyLabel(id uuid.UUID) (string, error) {
	stringUuid := id.String()
	if stringUuid == "" {
		return "invalid_UUID", fmt.Errorf("invalid UUID used for creating private key label")
	}
	return stringUuid + "_priv", nil
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

		// check error type and call the pkcs11 error handler to try to fix the error before trying again
		pkcs11Err, ErrTypeOk := err.(pkcs11.Error)
		if ErrTypeOk {
			err = E.pkcs11HandleGenericErrors(pkcs11Err)
			if err != nil { // the generic error handler thinks this is an unfixable error, return
				return err
			}
		} else {
			return fmt.Errorf("pkcs11Retry used on non-pkcs11-context function (returned error type is not pkcs11.Error)")
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

// pkcs11BytesToPublicKeyStruct converts the public key bytes as returned by the HSM (x,y) to an ecdsa.PublicKey struct.
func (E ECDSAPKCS11CryptoContext) pkcs11BytesToPublicKeyStruct(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != nistp256PubkeyLength {
		return nil, fmt.Errorf("pkcs11BytesToPublicKeyStruct: received invalid public key length: expected %d, got %d bytes", nistp256PubkeyLength, len(pubKeyBytes))
	}

	//create the key object
	pubkeyStruct := new(ecdsa.PublicKey)
	pubkeyStruct.Curve = elliptic.P256()
	pubkeyStruct.X = &big.Int{}
	pubkeyStruct.X.SetBytes(pubKeyBytes[0:nistp256XLength])
	pubkeyStruct.Y = &big.Int{}
	pubkeyStruct.Y.SetBytes(pubKeyBytes[nistp256XLength:(nistp256XLength + nistp256YLength)])

	if !pubkeyStruct.IsOnCurve(pubkeyStruct.X, pubkeyStruct.Y) {
		return nil, fmt.Errorf("pkcs11BytesToPublicKeyStruct:invalid public key value: point not on curve")
	}

	return pubkeyStruct, nil

}
