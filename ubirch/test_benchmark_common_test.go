/*
 * Copyright (c) 2019 ubirch GmbH.
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 * NOTE:
 * These testing functions include tests, which will fail, because the
 * tested libraries do not yet support the functionality.
 * To perform tests on the already implemented modules, use:
 *
 * `go test -v -test.run=.*([^N].....|[^O]....|[^T]...|[^R]..|[^D].|[^Y])$`
 *
 * which will skip all test with the name `Test...NOTRDY()`
 * To test against a pkcs#11 HSM interface use the following flags:
 * go test -test.run=.*([^N].....|[^O]....|[^T]...|[^R]..|[^D].|[^Y])$ -pkcs11CryptoTests -pkcs11LibLocation="/absolute/path/to/pkcs11.so" -pkcs11SlotUserPin="YourPin"
 * Be aware that some tests might take much longer with pkcs#11 interfaces so adjust the number of tests or skip them as needed.
 * You can use the -quickTests flag to do less thorough tests.
 */
//This file contains common test and benchmark functions as well as defaults
package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"io/ioutil"
	"math/big"
	insecuremathrand "math/rand"
	"os"
	"os/exec"
	"testing"
)

////Default Values////
// (for consistent defaults in benchmark/test table entries )
const (
	defaultUUID      = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"                                                                                             //"f9038b4b-d3bc-47c9-9968-ea275f1b6de8"
	defaultPriv      = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	defaultPub       = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
	defaultLastSig   = "c03821e1bbabebce351044168c5016187829bcf60988869f4d0bd3e8a905d38fa0bde9269042ad062262dd6829cc8def9e71e10d0a527671ca5707a436b1f209"
	defaultHash      = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	defaultInputData = "cafedeadbeef11223344556677889900aabbccddeeff"
	defaultDataSize  = 200
	defaultSecret    = "2234567890123456"
)

////Constants////
//constants to avoid 'magic numbers' in the code
const (
	lenPubkeyECDSA  = 64
	lenPrivkeyECDSA = 32
)

type ExtendedProtocol struct {
	Protocol
	signatures map[uuid.UUID][]byte
}

func NewExtendedProtocol(context Crypto, signatures map[uuid.UUID][]byte) *ExtendedProtocol {
	p := &ExtendedProtocol{}
	p.signatures = signatures
	p.Protocol.Crypto = context
	return p
}

// SignHash creates and signs a ubirch-protocol message using the given hash and the protocol version.
// The method expects a SHA256 hash as input data.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *ExtendedProtocol) SignHash(id uuid.UUID, hash []byte, protocol ProtocolVersion) ([]byte, error) {
	if hash == nil || len(hash) != p.HashLength() {
		return nil, fmt.Errorf("invalid hash size: expected %d, got %d bytes", p.HashLength(), len(hash))
	}

	switch protocol {
	case Signed:
		return p.Sign(&SignedUPP{Signed, id, Binary, hash, nil})
	case Chained:
		// get the signature of the last UPP
		prevSignature, found := p.signatures[id]
		if !found {
			prevSignature = make([]byte, nistp256SignatureLength) // not found: make new chain start (all zeroes signature)
		} else if len(prevSignature) != nistp256SignatureLength { // found: check that loaded signature has valid length
			return nil, fmt.Errorf("invalid last signature, can't create chained UPP")
		}

		// sign
		upp, err := p.Sign(&ChainedUPP{Chained, id, prevSignature, Binary, hash, nil})
		if err != nil {
			return nil, err
		}

		// set the new signature for the next chained UPP
		newSignature := upp[len(upp)-nistp256SignatureLength:]
		p.signatures[id] = newSignature

		return upp, nil

	default:
		return nil, fmt.Errorf("invalid protocol version: 0x%02x", protocol)
	}
}

// SignData creates and signs a ubirch-protocol message using the given user data and the protocol version.
// The method expects the user data as input data. Data will be SHA256 hashed and a UPP using
// the hash as payload will be created by calling SignHash(). The UUID is automatically retrieved
// from the context using the given device name.
func (p *ExtendedProtocol) SignData(id uuid.UUID, userData []byte, protocol ProtocolVersion) ([]byte, error) {
	//Catch errors
	if userData == nil || len(userData) < 1 {
		return nil, fmt.Errorf("input data is nil or empty")
	}
	//Calculate hash
	hash := sha256.Sum256(userData)

	return p.SignHash(id, hash[:], protocol)
}

//////Helper Functions//////

//parameterString prints a string showing the passed parameters as a block of text (for easier/ more helpful error messages)
//if the string is empty ("") the corresponding line is not added
func parameterString(uuidStr string, privkey string, pubkey string, lastSignature string) string {
	paramStr := ""

	if uuidStr != "" {
		paramStr += fmt.Sprintf("UUID: %v\n", uuidStr)
	}
	if privkey != "" {
		paramStr += fmt.Sprintf("PrivKey: %v\n", privkey)
	}
	if pubkey != "" {
		paramStr += fmt.Sprintf("PubKey: %v\n", pubkey)
	}
	if lastSignature != "" {
		paramStr += fmt.Sprintf("lastSig: %v\n", lastSignature)
	}

	return paramStr
}

//randomString returns a random string with a length between lenMin and lenMax
//all letters that are allowed in the string
func randomString(lenMin int, lenMax int) string {
	var letters = []rune(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")

	//generate the string
	stringlength := insecuremathrand.Intn((lenMax+1)-lenMin) + lenMin
	randString := make([]rune, stringlength)
	for i := range randString {
		randString[i] = letters[insecuremathrand.Intn(len(letters))]
	}
	return string(randString)
}

//loads a protocol context from a json file
func loadProtocolContext(p *ExtendedProtocol, filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contextBytes, p)
	return err
}

//saves a protocol context to a json file
func saveProtocolContext(p *ExtendedProtocol, filename string) error {
	contextBytes, _ := json.Marshal(p)
	err := ioutil.WriteFile(filename, contextBytes, 0666)
	return err
}

// deleteProtocolContext deletes the file, which holds the protocol Context
func deleteProtocolContext(filename string) error {
	// delete file
	var err = os.Remove(filename)
	return err
}

// Get the private key bytes for the given name.
func getPrivateKey(c *ECDSACryptoContext, id uuid.UUID) ([]byte, error) {
	privKeyBytes, err := c.Keystore.GetPrivateKey(id)
	if err != nil {
		return nil, err
	}
	return privKeyBytes, nil
}

//Creates a new protocol context for a UPP creator (privkey is passed, pubkey is calculated)
func newProtocolContextSigner(UUID string, PrivKey string, LastSignature string) (*ExtendedProtocol, error) {
	context, err := getCryptoContext()
	if err != nil {
		return nil, fmt.Errorf("newProtocolContextSigner: %s", err)
	}
	protocol := NewExtendedProtocol(context, map[uuid.UUID][]byte{})
	//Load reference data into context
	err = setProtocolContext(protocol, UUID, PrivKey, "", LastSignature)
	if err != nil {
		return nil, fmt.Errorf("newProtocolContextSigner: %s", err)
	}
	return protocol, nil
}

//Creates a new protocol context for a UPP verifier (only pubkey is needed)
func newProtocolContextVerifier(UUID string, PubKey string) (*ExtendedProtocol, error) {
	//create golang or pkcs#11 crypto context depending on test settings
	context, err := getCryptoContext()
	if err != nil {
		return nil, fmt.Errorf("newProtocolContextVerifier: %s", err)
	}
	protocol := NewExtendedProtocol(context, map[uuid.UUID][]byte{})
	//Load reference data into context
	err = setProtocolContext(protocol, UUID, "", PubKey, "")
	if err != nil {
		return nil, fmt.Errorf("newProtocolContextVerifier: %s", err)
	}
	return protocol, nil
}

//Sets the passed protocol context to the passed values (name, UUID, private Key, last signature), passed as hex strings
//If a value is an empty string ("") it will not be set. If privkey is given, pubkey will be calculated, but
//directly overwritten if an explicit pubkey is passed in
func setProtocolContext(p *ExtendedProtocol, UUID string, PrivKey string, PubKey string, LastSignature string) error {
	if p == nil {
		return fmt.Errorf("Protocol is nil")
	}

	id := uuid.Nil
	if UUID != "" {
		err := errors.New("")
		id, err = uuid.Parse(UUID)
		if err != nil {
			return err
		}
	}

	if PrivKey != "" {
		//Set private key (public key will automatically be calculated and set)
		privBytes, err := hex.DecodeString(PrivKey)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error decoding private key string: : %v, string was: %v", err, PrivKey)
		}
		if *pkcs11CryptoTests && *pkcs11CP5HSM { //on CP5 HSM simulators, use workaround for setting the key
			if PrivKey == defaultPriv { // if it's default key
				fmt.Println("setProtocolContext: warning: pkcs11CP5HSM flag set, can't use SetKey(defaultPriv), generating new keypair as workaround")
				err = p.Crypto.GenerateKey(id) //generate key
				if err != nil {
					return fmt.Errorf("setProtocolContext: Error gnerating private key as workaround: %v,", err)
				}
				err = pkcs11CP5HSMInitAndAuthorizeKey(p.Crypto, id) //activate key
				if err != nil {
					return fmt.Errorf("setProtocolContext: Error activating key: %v,", err)
				}
			} else { // test wants specific key, we can't do that, return error
				return fmt.Errorf("setProtocolContext: pkcs11CP5HSM flag set, can't use SetKey(%s)", PrivKey)
			}
		} else { //for 'normal' tests, just set the key
			err = p.Crypto.SetKey(id, privBytes)
			if err != nil {
				return fmt.Errorf("setProtocolContext: Error setting private key bytes: %v,", err)
			}
		}
	}

	if PubKey != "" {
		//Catch errors
		if UUID == "" {
			return fmt.Errorf("Need UUID to set public key")
		}
		//Set public key
		pubBytes, err := hex.DecodeString(PubKey)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error decoding public key string: : %v, string was: %v", err, PubKey)
		}
		err = p.Crypto.SetPublicKeyBytes(id, pubBytes)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error setting public key bytes: : %v,", err)
		}
	}

	if LastSignature != "" {
		//catch errors
		if UUID == "" {
			return fmt.Errorf("Need UUID to set last signature")
		}
		//Set last Signature
		lastSigBytes, err := hex.DecodeString(LastSignature)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error decoding last signature string: : %v, string was: %v", err, LastSignature)
		}
		if len(lastSigBytes) != 64 {
			return fmt.Errorf("Last signature to set is != 64 bytes")
		}
		p.signatures[id] = lastSigBytes
	}

	return nil
}

//create golang or pkcs#11 crypto context depending on test settings
func getCryptoContext() (Crypto, error) {
	if *pkcs11CryptoTests { // if pkcs#11 interface should be used
		context, err := NewECDSAPKCS11CryptoContext(
			*pkcs11LibLocation,
			*pkcs11SlotUserPin,
			0,
			false,
			0,
			0)
		if err != nil {
			return nil, fmt.Errorf("creating new pkcs#11 crypto context failed: %s", err)
		}
		// open a session and login to the HSM/pkcs#11 device
		err = context.SetupSession()
		if err != nil {
			return nil, fmt.Errorf("setting up session with pkcs#11 crypto interface failed: %s", err)
		}
		return context, nil
	} else {
		context := &ECDSACryptoContext{
			Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
		}
		return context, nil
	}
}

//Generates reproducible pseudorandom data using a simple linear congruental generator.
//NEVER us this for something other than generating bogus input data.
func deterministicPseudoRandomBytes(seed int32, size int) []byte {
	block := make([]byte, size)
	//We use the same parameters used in the "simple" version of glibc's rand()
	//and simply fill the block with the generated numbers.
	for index := range block {
		seed = (1103515245*seed + 12345) & 0x7fffffff
		block[index] = byte(seed)
	}
	return block
}

//Do a verification of the UPP signature with the go ecdsa library
func verifyUPPSignature(t *testing.T, uppBytes []byte, pubkeyBytes []byte) (bool, error) {
	//Check that UPP data is OK in general
	if len(pubkeyBytes) != 64 {
		return false, fmt.Errorf("pubkey is not 64 bytes long")
	}
	if len(uppBytes) <= 66 { //check for minimal UPP packet size
		return false, fmt.Errorf("UPP data is too short (%v bytes)", len(uppBytes))
	}

	//Extract signature, data, and hash of data from UPP
	signature := uppBytes[len(uppBytes)-64:]
	dataToHash := uppBytes[:len(uppBytes)-66]
	hash := sha256.Sum256(dataToHash)

	//Set variables so they are in the format the ecdsa lib expects them
	x := &big.Int{}
	x.SetBytes(pubkeyBytes[0:32])
	y := &big.Int{}
	y.SetBytes(pubkeyBytes[32:64])
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	//Do the verification and return result
	verifyOK := ecdsa.Verify(&pubkey, hash[:], r, s)
	return verifyOK, nil
}

//Do a verification of the UPP chain ("lastSignature" in "chained" packets must be the signature of previous UPP)
//data is passed in as an array of byte arrays, each representing one UPP in correct order
//startSignature is the signature before the first packet in the array (=lastSignature in first UPP)
//returns no error if chain verification passes
func verifyUPPChain(t *testing.T, uppsArray [][]byte, startSignature []byte) error {
	if len(uppsArray) == 0 {
		return fmt.Errorf("UPP array is empty")
	}
	expectedUPPlastSig := startSignature
	//iterate over all UPPs in array
	for currUppIndex, currUppData := range uppsArray {
		//Check that this UPP's data is OK in general
		//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
		if len(currUppData) < (1 + 16 + 64 + 1 + 0 + 64) { //check for minimal UPP packet size (VERSION|UUID|PREV-SIGNATURE|TYPE|PAYLOAD|SIGNATURE)
			return fmt.Errorf("UPP data is too short (%v bytes) at UPP index %v", len(currUppData), currUppIndex)
		}
		//copy "last signature" field of current UPP and compare to expectation
		//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
		currUppLastSig := currUppData[22 : 22+64]
		if !bytes.Equal(expectedUPPlastSig, currUppLastSig) {
			return fmt.Errorf("Signature chain mismatch between UPPs at index %v and %v", currUppIndex, currUppIndex-1)
		}
		//save signature of this packet as expected "lastSig" for next packet
		expectedUPPlastSig = currUppData[len(currUppData)-64:]
	}
	//If we reach this, everything was checked without errors
	return nil
}

//checkSignedUPP checks a signed type UPP. Parameters are passed as strings.
//The following checks are performed: signature OK, decoding works, payload as expected
//If everything is OK no error is returned, else the error indicates the failing check.
func checkSignedUPP(t *testing.T, uppData []byte, expectedPayload string, pubKey string) error {
	//Decode Pubkey for checking UPPs
	pubkeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("Test configuration string (pubkey) can't be decoded.\nString was: %v", pubKey)
	}

	//Check each signed UPP...
	//...decoding/payload
	decodedSigned, err := Decode(uppData)
	if err != nil {
		return fmt.Errorf("UPP could not be decoded")
	}
	signed := decodedSigned.(*SignedUPP)
	expectedPayloadBytes, err := hex.DecodeString(expectedPayload)
	if err != nil {
		return fmt.Errorf("Test configuration string (expectedPayload) can't be decoded. \nString was: %v", expectedPayload)
	}
	if !bytes.Equal(expectedPayloadBytes[:], signed.Payload) {
		return fmt.Errorf("Payload does not match expectation.\nExpected:\n%v\nGot:\n%v", hex.EncodeToString(expectedPayloadBytes[:]), hex.EncodeToString(signed.Payload))
	}
	//...Signature
	verifyOK, err := verifyUPPSignature(t, uppData, pubkeyBytes)
	if err != nil {
		return fmt.Errorf("Signature verification could not be performed, error: %v", err)
	}
	if !verifyOK {
		return fmt.Errorf("Signature is not OK")
	}

	//If we reach this, everything was checked without errors
	return nil
}

//checkChainedUPPs checks an array of chained type UPPs. Parameters are passed as strings.
//The following checks are performed: signatures OK, decoding works, payload as expected, chaining OK
//If everything is OK no error is returned, else the error indicates the failing check.
func checkChainedUPPs(t *testing.T, uppsArray [][]byte, expectedPayloads []string, startSignature string, pubKey string) error {
	//Catch general errors
	if len(uppsArray) == 0 {
		return fmt.Errorf("UPP array is empty")
	}
	if len(uppsArray) != len(expectedPayloads) {
		return fmt.Errorf("Number of UPPs and expected payloads not equal")
	}
	//Decode Pubkey for checking UPPs
	pubkeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("Test configuration string (pubkey) can't be decoded.\nString was: %v", pubKey)
	}
	//Decode last signature
	lastSigBytes, err := hex.DecodeString(startSignature)
	if err != nil {
		return fmt.Errorf("Test configuration string (startSig) can't be decoded.\nString was: %v", startSignature)
	}

	//Check each chained UPP...
	for chainedUppIndex, chainedUppData := range uppsArray {
		//...decoding/payload/hash
		decodedChained, err := Decode(chainedUppData)
		if err != nil {
			return fmt.Errorf("UPP could not be decoded for UPP at index %v, error: %v", chainedUppIndex, err)
		}
		chained := decodedChained.(*ChainedUPP)
		expectedPayload, err := hex.DecodeString(expectedPayloads[chainedUppIndex])
		if err != nil {
			return fmt.Errorf("Test configuration string (expectedPayload) can't be decoded at index %v.\nString was: %v", chainedUppIndex, expectedPayloads[chainedUppIndex])
		}
		if !bytes.Equal(expectedPayload[:], chained.Payload) {
			return fmt.Errorf("Payload does not match expectation for UPP at index %v\nExpected:\n%v\nGot:\n%v", chainedUppIndex, hex.EncodeToString(expectedPayload[:]), hex.EncodeToString(chained.Payload))
		}
		//...Signature
		verifyOK, err := verifyUPPSignature(t, chainedUppData, pubkeyBytes)
		if err != nil {
			return fmt.Errorf("Signature verification could not be performed due to errors for UPP at index %v, error: %v", chainedUppIndex, err)
		}
		if !verifyOK {
			return fmt.Errorf("Signature is not OK for UPP at index %v", chainedUppIndex)
		}
	}
	//... check chain iself
	err = verifyUPPChain(t, uppsArray, lastSigBytes)
	if err != nil {
		return err //return the info from the chain check error
	}
	//If we reach this, everything was checked without errors
	return nil
}

func encodePrivateKeyTestHelper(privKeyBytes []byte) ([]byte, error) {
	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	x509Encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

func encodePublicKeyTestHelper(pubKeyBytes []byte) ([]byte, error) {
	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:32])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[32:64])

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, nil
}

func decodePrivateKeyTestHelper(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

func decodePublicKeyTestHelper(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

// pkcs11DeletePrivateKey deletes the private key for a certain UUID from an HSM. Used to clean up after tests.
// Session must be already established, logged in, and read/write. Returns without error if key does not exist.
func (E *ECDSAPKCS11CryptoContext) pkcs11DeletePrivateKey(id uuid.UUID) error {
	keyExists, err := E.PrivateKeyExists(id)
	if err != nil {
		return err
	}
	if !keyExists {
		return nil
	}

	// get handle and delete object
	handle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return err
	}
	err = E.pkcs11Ctx.DestroyObject(E.sessionHandle, handle)
	if err != nil {
		return err
	}
	return nil
}

// pkcs11DeletePublicKey deletes the public key for a certain UUID from an HSM. Used to clean up after tests.
// Session must be already established, logged in, and read/write. Returns without error if key does not exist.
func (E *ECDSAPKCS11CryptoContext) pkcs11DeletePublicKey(id uuid.UUID) error {
	keyExists, err := E.PublicKeyExists(id)
	if err != nil {
		return err
	}
	if !keyExists {
		return nil
	}

	// get handle and delete object
	handle, err := E.pkcs11GetHandle(id, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return err
	}
	err = E.pkcs11Ctx.DestroyObject(E.sessionHandle, handle)
	if err != nil {
		return err
	}
	return nil
}

// pkcs11DeleteKeypair deletes a keypair for a certain UUID from an HSM. Used to clean up after tests.
// Session must be already established, logged in, and read/write. Existence of keypair is determined via
// private key only. If keys are not found function returns without an error.
func pkcs11DeleteKeypair(context Crypto, id uuid.UUID) error {

	err := context.(*ECDSAPKCS11CryptoContext).pkcs11DeletePrivateKey(id)
	if err != nil {
		return fmt.Errorf("deleting private key of keypair for uuid %s from HSM failed: %s", id, err)
	}
	err = context.(*ECDSAPKCS11CryptoContext).pkcs11DeletePublicKey(id)
	if err != nil {
		return fmt.Errorf("deleting public key of keypair for uuid %s from HSM failed: %s", id, err)
	}

	return nil
}

// pkcs11CP5HSMInitAndAuthorizeKey initializes and authorizes a freshly generated key during tests. This is a procedure
// needed on CP5 HSMs before using the keys. This simply calls a bash script with one argument: the label of the private
// key to authorize and initialize. A suitable bash script can be pulled with the HSM helper scripts repo and a symbolic
// link created.
func pkcs11CP5HSMInitAndAuthorizeKey(context Crypto, id uuid.UUID) error {

	keyLabel, err := context.(*ECDSAPKCS11CryptoContext).pkcs11PrivKeyLabel(id)
	if err != nil {
		return fmt.Errorf("could not get private key label: %s", err)
	}

	cmd := exec.Command("./tests_key_init_and_authorize.sh", keyLabel)
	cmdStdout, err := cmd.Output()
	cmdStdoutStr := string(cmdStdout)
	if err != nil {
		errMessage := "" // for building error with all script info
		errMessage += "pkcs11CP5HSMInitAndAuthorizeKey: error during script execution\n"
		errMessage += fmt.Sprintf("cmd.Output() returned: %s\n", err)
		if len(cmdStdoutStr) > 0 { // print stdout if available
			errMessage += fmt.Sprintf("\nstdout:\n%s", cmdStdoutStr)
		}
		// also get + print stderr output if available
		_, isExitError := err.(*exec.ExitError)
		if isExitError {
			errMessage += fmt.Sprintf("\nstderr:\n%s", string(err.(*exec.ExitError).Stderr))
		}
		return fmt.Errorf(errMessage)
	}
	return nil
}
