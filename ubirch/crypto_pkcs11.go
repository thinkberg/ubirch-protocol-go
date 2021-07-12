package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

type ECDSAPKCS11CryptoContext struct {
	pkcs11Ctx        *pkcs11.Ctx          // pkcs11 context for accessing HSM interface
	sessionHandle    pkcs11.SessionHandle // Handle of pkcs11 session
	loginPIN         string               // PIN for logging into the pkcs#11 session
	slotNr           int                  // pkcs#11 slot number to use (zero-based)
	sessionFlags     uint                 // flags used when opening the session
	pkcs11Retries    int                  // how often to retry in case of pkcs#11 errors
	pkcs11RetryDelay time.Duration        // how long to pause before retrying after pkcs#11 errors

	signMtx *sync.Mutex
}

var _ Crypto = (*ECDSAPKCS11CryptoContext)(nil)

// NewECDSAPKCS11CryptoContext initializes the pkcs#11 crypto context including login and session.
// Parameters:
// pkcs11LibLocation: path where to find the .so/.dll pkcs#11 interface file. Use full path or properly configured environment.
// loginPIN: PIN for authenticating the pkcs11 USER (as opposed to the security officer)
// slotNr: which pkcs#11 slot to use
// readOnlySession: only allow operation which don't change the token (e.g. sign, verify OK, but generate, delete keys not OK)
// pkcs11Retries: how often to retry in case of errors, set to 0 to disable generic error handling like re-establishing sessions
// pkcs11RetryDelay: delay for retrying for handling of certain errors, see pkcs11HandleGenericErrors() for details
func NewECDSAPKCS11CryptoContext(pkcs11LibLocation string, loginPIN string, slotNr int, readOnlySession bool, pkcs11Retries int, pkcs11RetryDelay time.Duration) (*ECDSAPKCS11CryptoContext, error) {
	E := new(ECDSAPKCS11CryptoContext)

	E.pkcs11Ctx = pkcs11.New(pkcs11LibLocation)
	if E.pkcs11Ctx == nil {
		return nil, fmt.Errorf("NewECDSAPKCS11CryptoContext: failed to create new pkcs11Ctx with library '%s'", pkcs11LibLocation)
	}

	E.loginPIN = loginPIN
	E.slotNr = slotNr
	E.pkcs11Retries = pkcs11Retries
	E.pkcs11RetryDelay = pkcs11RetryDelay
	if !readOnlySession { // if this should be a session with read/write access (e.g. generate or set keys)
		E.sessionFlags = pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION
	} else { // read-only session (e.g. only sign and verify)
		E.sessionFlags = pkcs11.CKF_SERIAL_SESSION
	}

	err := E.pkcs11SetupSession()
	if err != nil {
		return nil, fmt.Errorf("NewECDSAPKCS11CryptoContext: %s", err)
	}

	E.signMtx = &sync.Mutex{}

	return E, nil
}

// Close closes/logs out of the pkcs#11 session and destroys the pkcs#11 context
func (E *ECDSAPKCS11CryptoContext) Close() error {

	err := E.pkcs11TeardownSession()
	if err != nil {
		return err
	}

	E.pkcs11Ctx.Destroy()

	return nil
}

// GetPublicKey gets the binary public key data as returned by the HSM
func (E *ECDSAPKCS11CryptoContext) GetPublicKey(id uuid.UUID) ([]byte, error) {
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
	_, err = PublicKeyBytesToStruct(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return pubKeyBytes, nil
}

// SetPublicKey sets the public key only. Use SetKey() instead to create a working keypair from a private key.
func (E *ECDSAPKCS11CryptoContext) SetPublicKey(id uuid.UUID, pubKeyBytes []byte) error {
	// Sanity checks
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}
	_, err := PublicKeyBytesToStruct(pubKeyBytes)
	if err != nil {
		return err
	}

	//check key does not exist
	pubExists, err := E.PublicKeyExists(id)
	if err != nil {
		return fmt.Errorf("SetPublicKey: checking public key existence failed: %s", err)
	}
	if pubExists {
		return fmt.Errorf("SetPublicKey: public key already exists")
	}

	// create template from pub key bytes, add DER encoding header
	pubKeyBytesHSM := []byte{0x04, nistp256PubkeyLength + 1, 0x04} // header = 0x04 'octet string' + length + 0x04 'uncompressed public key'
	pubKeyBytesHSM = append(pubKeyBytesHSM, pubKeyBytes[:]...)

	pubKeyTemplate, err := E.pkcs11PubKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("SetPublicKey: could not get public key template: %s", err)
	}
	pubKeyTemplate = append(pubKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pubKeyBytesHSM)) // add the DER-encoding of ANSI X9.62 ECPoint value Q

	// write pub key to HSM
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, err := E.pkcs11Ctx.CreateObject(E.sessionHandle, pubKeyTemplate)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("SetPublicKey: %s", retriedErr)
	}
	return nil
}

func (E *ECDSAPKCS11CryptoContext) PrivateKeyExists(id uuid.UUID) (bool, error) {
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

func (E *ECDSAPKCS11CryptoContext) PublicKeyExists(id uuid.UUID) (bool, error) {
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
func (E *ECDSAPKCS11CryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}

	privKey, err := PrivateKeyBytesToStruct(privKeyBytes)
	if err != nil {
		return err
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

	//create keypair bytes
	var bytesX [nistp256XLength]byte
	var bytesY [nistp256XLength]byte
	privKey.PublicKey.X.FillBytes(bytesX[:])
	privKey.PublicKey.Y.FillBytes(bytesY[:])

	var pubKeyBytes []byte
	pubKeyBytes = append(pubKeyBytes, bytesX[:]...) // append X
	pubKeyBytes = append(pubKeyBytes, bytesY[:]...) // append Y

	var privKeyBytesHSM [nistp256PrivkeyLength]byte
	privKey.D.FillBytes(privKeyBytesHSM[:])
	privKeyTemplate, err := E.pkcs11PrivKeyTemplate(id)
	if err != nil {
		return fmt.Errorf("SetKey: could not get private key template: %s", err)
	}
	privKeyTemplate = append(privKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKeyBytesHSM[:])) // add the X9.62 private value d
	privKeyTemplate = append(privKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, "secp256r1"))    // normally derived from public key, but must be explicit here

	//write keys to HSM
	err = E.SetPublicKey(id, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("SetKey: %s", err)
	}
	retriedErr := E.pkcs11Retry(E.pkcs11Retries, E.pkcs11RetryDelay, func() error {
		_, err := E.pkcs11Ctx.CreateObject(E.sessionHandle, privKeyTemplate)
		return err
	})
	if retriedErr != nil {
		return fmt.Errorf("SetKey: failed to set private key: %s", retriedErr)
	}

	return nil
}

// GenerateKey generates a new keypair using standard templates
func (E *ECDSAPKCS11CryptoContext) GenerateKey(id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("GenerateKey: UUID \"Nil\"-value")
	}

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

// GetCSR gets a certificate signing request.
func (E *ECDSAPKCS11CryptoContext) GetCSR(id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error) {
	hsmPrivateKey, err := newPKCS11ECDSAPrivKey(id, E)
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

func (E *ECDSAPKCS11CryptoContext) SignatureLength() int {
	return nistp256SignatureLength
}

func (E *ECDSAPKCS11CryptoContext) HashLength() int {
	return sha256Length
}

// Sign creates the signature for arbitrary data using the private key of the given UUID
func (E *ECDSAPKCS11CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hash := sha256.Sum256(data)
	return E.SignHash(id, hash[:])
}

// SignHash retrieves the signature for an already computed SHA-256 hash using the private key of the given UUID from the HSM.
func (E *ECDSAPKCS11CryptoContext) SignHash(id uuid.UUID, hash []byte) ([]byte, error) {
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}

	E.signMtx.Lock()
	defer E.signMtx.Unlock()

	keyHandle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, fmt.Errorf("SignHash: getting key handle: %s", err)
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
func (E *ECDSAPKCS11CryptoContext) Verify(id uuid.UUID, data []byte, signature []byte) (bool, error) {
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
	pub, err := PublicKeyBytesToStruct(pubkeyBytes)
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
func (E *ECDSAPKCS11CryptoContext) pkcs11PubKeyTemplate(id uuid.UUID) ([]*pkcs11.Attribute, error) {
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
func (E *ECDSAPKCS11CryptoContext) pkcs11PubKeyLabel(id uuid.UUID) (string, error) {
	stringUuid := id.String()
	if stringUuid == "" {
		return "invalid_UUID", fmt.Errorf("invalid UUID used for creating public key label")
	}
	return stringUuid + "_pub", nil
}

// pkcs11PrivKeyTemplate returns the standard private key template, errors if UUID is invalid
func (E *ECDSAPKCS11CryptoContext) pkcs11PrivKeyTemplate(id uuid.UUID) ([]*pkcs11.Attribute, error) {
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
func (E *ECDSAPKCS11CryptoContext) pkcs11PrivKeyLabel(id uuid.UUID) (string, error) {
	stringUuid := id.String()
	if stringUuid == "" {
		return "invalid_UUID", fmt.Errorf("invalid UUID used for creating private key label")
	}
	return stringUuid + "_priv", nil
}

// gets objects of a certain class with a certain ID (CKA_ID = byte array), which usually is the device UUID bytes, returns up to 'max' objects
func (E *ECDSAPKCS11CryptoContext) pkcs11GetObjects(pkcs11id []byte, class uint, max int) ([]pkcs11.ObjectHandle, error) {
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
func (E *ECDSAPKCS11CryptoContext) pkcs11GetHandle(id uuid.UUID, class uint) (pkcs11.ObjectHandle, error) {
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
// The original error from the pkcs11 package must be passed in as the argument. Sleep time is only used in appropriate cases.
// Returns nil if the error was fixed or should be retried, or the original error if it is deemed unfixable.
func (E *ECDSAPKCS11CryptoContext) pkcs11HandleGenericErrors(pkcs11Error pkcs11.Error, sleep time.Duration) error {
	if pkcs11Error == pkcs11.CKR_OK {
		return nil //exit immediately if there was no error
	}

	returnCode := uint(pkcs11Error)
	// There are basically three ways of handling errors: waiting and trying again, re-establish session, and deeming it 'unfixable'
	// A combination of waiting and re-establishing the session is also possible.
	switch returnCode {
	//'retry' errors, includes errors which might be fixed by retransmission of data (e.g. flaky UART connection)
	case pkcs11.CKR_HOST_MEMORY,
		pkcs11.CKR_FUNCTION_FAILED,
		pkcs11.CKR_DATA_INVALID,
		pkcs11.CKR_DATA_LEN_RANGE,
		pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_DEVICE_MEMORY,
		pkcs11.CKR_ENCRYPTED_DATA_INVALID,
		pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE,
		pkcs11.CKR_KEY_SIZE_RANGE,
		pkcs11.CKR_KEY_INDIGESTIBLE,
		pkcs11.CKR_SESSION_COUNT,
		pkcs11.CKR_SIGNATURE_INVALID,
		pkcs11.CKR_SIGNATURE_LEN_RANGE,
		pkcs11.CKR_TOKEN_NOT_PRESENT,
		pkcs11.CKR_USER_TOO_MANY_TYPES,
		pkcs11.CKR_WRAPPED_KEY_INVALID,
		pkcs11.CKR_WRAPPED_KEY_LEN_RANGE,
		pkcs11.CKR_PUBLIC_KEY_INVALID:
		//simply wait and try again
		jitter := sleep * time.Duration(rand.Float32()/20.0) * sleep // add up to 5% jitter to avoid 'thundering herd' and possibly fix timing problems
		time.Sleep(sleep + jitter)                                   // simply wait a bit before trying again and hope the error goes away
		return nil

	case pkcs11.CKR_DEVICE_REMOVED: // if the device was removed/offline, we want to give it time to come back, then re-login (via fallthrough)
		jitter := sleep * time.Duration(rand.Float32()/20.0) * sleep // add up to 5% jitter to avoid 'thundering herd' and possibly fix timing problems
		time.Sleep(sleep + jitter)                                   //  wait a bit before trying again and hope HSM goes online again
		fallthrough                                                  //we also want to re-establish the session (via the next block)

	// 're-establish session' errors
	case pkcs11.CKR_OPERATION_ACTIVE,
		pkcs11.CKR_OPERATION_NOT_INITIALIZED,
		pkcs11.CKR_SESSION_CLOSED,
		pkcs11.CKR_SESSION_HANDLE_INVALID,
		pkcs11.CKR_SESSION_EXISTS,
		pkcs11.CKR_USER_ALREADY_LOGGED_IN,
		pkcs11.CKR_USER_NOT_LOGGED_IN,
		pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED,
		pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED:
		//reset session through teardown/setup
		err := E.pkcs11TeardownSession()
		if err != nil {
			return fmt.Errorf("pkcs11HandleGenericErrors: Error when tearing down session: %s", err)
		}
		err = E.pkcs11SetupSession()
		if err != nil {
			return fmt.Errorf("pkcs11HandleGenericErrors: Error when setting up session: %s", err)
		}
		return nil

	//'unfixable' errors
	case pkcs11.CKR_GENERAL_ERROR,
		pkcs11.CKR_ARGUMENTS_BAD,
		pkcs11.CKR_SLOT_ID_INVALID,
		pkcs11.CKR_NO_EVENT,
		pkcs11.CKR_NEED_TO_CREATE_THREADS,
		pkcs11.CKR_CANT_LOCK,
		pkcs11.CKR_ATTRIBUTE_READ_ONLY,
		pkcs11.CKR_ATTRIBUTE_SENSITIVE,
		pkcs11.CKR_ATTRIBUTE_TYPE_INVALID,
		pkcs11.CKR_ATTRIBUTE_VALUE_INVALID,
		pkcs11.CKR_ACTION_PROHIBITED,
		pkcs11.CKR_FUNCTION_CANCELED,
		pkcs11.CKR_FUNCTION_NOT_PARALLEL,
		pkcs11.CKR_FUNCTION_NOT_SUPPORTED,
		pkcs11.CKR_KEY_HANDLE_INVALID,
		pkcs11.CKR_KEY_TYPE_INCONSISTENT,
		pkcs11.CKR_KEY_NOT_NEEDED,
		pkcs11.CKR_KEY_CHANGED,
		pkcs11.CKR_KEY_NEEDED,
		pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED,
		pkcs11.CKR_KEY_NOT_WRAPPABLE,
		pkcs11.CKR_KEY_UNEXTRACTABLE,
		pkcs11.CKR_MECHANISM_INVALID,
		pkcs11.CKR_MECHANISM_PARAM_INVALID,
		pkcs11.CKR_OBJECT_HANDLE_INVALID,
		pkcs11.CKR_PIN_INCORRECT,
		pkcs11.CKR_PIN_INVALID,
		pkcs11.CKR_PIN_LEN_RANGE,
		pkcs11.CKR_PIN_EXPIRED,
		pkcs11.CKR_PIN_LOCKED,
		pkcs11.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
		pkcs11.CKR_SESSION_READ_ONLY,
		pkcs11.CKR_SESSION_READ_ONLY_EXISTS,
		pkcs11.CKR_SESSION_READ_WRITE_SO_EXISTS,
		pkcs11.CKR_TEMPLATE_INCOMPLETE,
		pkcs11.CKR_TEMPLATE_INCONSISTENT,
		pkcs11.CKR_TOKEN_NOT_RECOGNIZED,
		pkcs11.CKR_TOKEN_WRITE_PROTECTED,
		pkcs11.CKR_UNWRAPPING_KEY_HANDLE_INVALID,
		pkcs11.CKR_UNWRAPPING_KEY_SIZE_RANGE,
		pkcs11.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
		pkcs11.CKR_USER_PIN_NOT_INITIALIZED,
		pkcs11.CKR_USER_TYPE_INVALID,
		pkcs11.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		pkcs11.CKR_WRAPPING_KEY_HANDLE_INVALID,
		pkcs11.CKR_WRAPPING_KEY_SIZE_RANGE,
		pkcs11.CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
		pkcs11.CKR_RANDOM_SEED_NOT_SUPPORTED,
		pkcs11.CKR_RANDOM_NO_RNG,
		pkcs11.CKR_DOMAIN_PARAMS_INVALID,
		pkcs11.CKR_CURVE_NOT_SUPPORTED,
		pkcs11.CKR_BUFFER_TOO_SMALL,
		pkcs11.CKR_SAVED_STATE_INVALID,
		pkcs11.CKR_INFORMATION_SENSITIVE,
		pkcs11.CKR_STATE_UNSAVEABLE,
		pkcs11.CKR_MUTEX_BAD,
		pkcs11.CKR_MUTEX_NOT_LOCKED,
		pkcs11.CKR_NEW_PIN_MODE,
		pkcs11.CKR_NEXT_OTP,
		pkcs11.CKR_EXCEEDED_MAX_ITERATIONS,
		pkcs11.CKR_FIPS_SELF_TEST_FAILED,
		pkcs11.CKR_LIBRARY_LOAD_FAILED,
		pkcs11.CKR_PIN_TOO_WEAK,
		pkcs11.CKR_FUNCTION_REJECTED,
		pkcs11.CKR_VENDOR_DEFINED:
		// unfixable, simply pass error back ('No, YOU deal with this.')
		return pkcs11Error
	// above cases should include all possible return values, so raise error if unknown error occurs
	default:
		return fmt.Errorf("pkcs11HandleGenericErrors: don't know how to handle error: %s", pkcs11Error)
	}
}

//pkcs11Retry is a helper function that retries a pkcs#11 function a defined number of times with an optional sleep delay.
// The passed-in function must return a pkcs11.Error, as its error is passed to pkcs11HandleGenericErrors. Thus this should
// only be used with E.pkcs11Ctx.(...) functions. Setting maxRetries to 0 will disable retrying and the generic error handler and
// pass any occurring errors directly back to the caller.
// The sleep delay is passed to pkcs11HandleGenericErrors and only used if sensible for the type of error.
// If the function to retry returns more than just an error use an anonymous function inline declaration in the calling
// context to set the variables you need within the scope of the calling function.
func (E *ECDSAPKCS11CryptoContext) pkcs11Retry(maxRetries int, sleep time.Duration, f func() error) error {
	for retries := 0; ; retries++ {
		err := f()
		if err == nil { // everything went fine, return
			return nil
		}
		if retries >= maxRetries { // we have tried too often, return
			return fmt.Errorf("pkcs11Retry: gave up after %d retries, last error was: %s", retries, err)
		}

		// check error type and call the pkcs11 error handler to try to fix the error before trying again
		pkcs11Err, ErrTypeOk := err.(pkcs11.Error)
		if ErrTypeOk {
			err = E.pkcs11HandleGenericErrors(pkcs11Err, sleep)
			if err != nil { // the generic error handler thinks this is an unfixable error, return directly
				return fmt.Errorf("pkcs11Retry: unfixable error: %s", err)
			}
		} else {
			return fmt.Errorf("pkcs11Retry used on non-pkcs11-context function (returned error type is not pkcs11.Error)")
		}

		//try again in next loop...
	}
}

//pkcs11SetupSession sets up a session including initialization and login.
func (E *ECDSAPKCS11CryptoContext) pkcs11SetupSession() error {
	// Warning: we can't use the retry handler in here, as the retry handler calls pkcs11SetupSession via the generic error handler
	// and this will lead to a recursion.
	//TODO: maybe better to check status of session then do steps as needed

	//initialize
	err := E.pkcs11Ctx.Initialize()
	if err != nil { // if there was an error
		pkcs11Err, typeOK := err.(pkcs11.Error) // assert that it's pkcs11 type
		if typeOK {                             //assertion worked
			if pkcs11Err != pkcs11.CKR_OK && pkcs11Err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED { //if it's not something that's ok
				return fmt.Errorf("pkcs11SetupSession: %s", pkcs11Err)
			}
		} else { //error is of unexpected type
			return fmt.Errorf("pkcs11SetupSession: unexpected type of error returned from intialize (not err.(pkcs11.Error)). Error was: %s", err)
		}
	}

	// get the slots
	slots, err := E.pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("pkcs11SetupSession: getting slot list: %s", err)
	}
	if len(slots) == 0 {
		return fmt.Errorf("pkcs11SetupSession: no slots with token present available")
	}

	//open a session
	E.sessionHandle, err = E.pkcs11Ctx.OpenSession(slots[E.slotNr], E.sessionFlags)
	if err != nil {
		return fmt.Errorf("pkcs11SetupSession: opening session: %s", err)
	}

	//login
	err = E.pkcs11Ctx.Login(E.sessionHandle, pkcs11.CKU_USER, E.loginPIN)
	if err != nil {
		return fmt.Errorf("pkcs11SetupSession: logging in: %s", err)
	}
	return nil
}

// pkcs11TeardownSession closes and finalizes a session including logout. At the end, the cryptoki lib should be in
// the 'uninitialized' state. (I.e. the last executed call is C_FINALIZE().)
func (E *ECDSAPKCS11CryptoContext) pkcs11TeardownSession() error {
	// Warning: we can't use the retry handler in here, as the retry handler calls pkcs11TeardownSession via the generic error handler
	// and this will lead to a recursion.
	var err error

	//logout
	err = E.pkcs11Ctx.Logout(E.sessionHandle)
	if err != nil { // if there was an error
		pkcs11Err, typeOK := err.(pkcs11.Error) // assert that it's pkcs11 type
		if typeOK {                             //assertion worked
			if pkcs11Err != pkcs11.CKR_OK &&
				pkcs11Err != pkcs11.CKR_DEVICE_REMOVED &&
				pkcs11Err != pkcs11.CKR_SESSION_CLOSED { //if it's not something that's ok or ok-ish (lost TCP/IP connection)
				return fmt.Errorf("pkcs11TeardownSession: logout: %s", pkcs11Err)
			}
		} else { //error is of unexpected type
			return fmt.Errorf("pkcs11TeardownSession: unexpected type of error returned from logout (not err.(pkcs11.Error)). Error was: %s", err)
		}
	}

	//close session
	err = E.pkcs11Ctx.CloseSession(E.sessionHandle)
	if err != nil { // if there was an error
		pkcs11Err, typeOK := err.(pkcs11.Error) // assert that it's pkcs11 type
		if typeOK {                             //assertion worked
			if pkcs11Err != pkcs11.CKR_OK &&
				pkcs11Err != pkcs11.CKR_DEVICE_REMOVED &&
				pkcs11Err != pkcs11.CKR_SESSION_CLOSED { //if it's not something that's ok or ok-ish (lost TCP/IP connection)
				return fmt.Errorf("pkcs11TeardownSession: close: %s", pkcs11Err)
			}
		} else { //error is of unexpected type
			return fmt.Errorf("pkcs11TeardownSession: unexpected type of error returned from close (not err.(pkcs11.Error)). Error was: %s", err)
		}
	}

	//finalize
	err = E.pkcs11Ctx.Finalize()
	if err != nil {
		return fmt.Errorf("pkcs11TeardownSession: finalize: %s", err)
	}

	return nil
}
