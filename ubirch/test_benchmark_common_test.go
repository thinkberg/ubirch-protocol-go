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
 */
//This file contains common test and benchmark functions as well as defaults
package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

////Default Values////
// (for consistent defaults in benchmark/test table entries )
const (
	defaultName     = "A"
	defaultUUID     = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"                                                                                             //"f9038b4b-d3bc-47c9-9968-ea275f1b6de8"
	defaultPriv     = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	defaultPub      = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
	defaultLastSig  = "c03821e1bbabebce351044168c5016187829bcf60988869f4d0bd3e8a905d38fa0bde9269042ad062262dd6829cc8def9e71e10d0a527671ca5707a436b1f209"
	defaultHash     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	defaultDataSize = 200
)

//////Helper Functions//////

//loads a protocol context from a json file
func loadProtocolContext(p *Protocol, filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contextBytes, p)
	return err
}

//saves a protocol context to a json file
func saveProtocolContext(p *Protocol, filename string) error {
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

// Get the public key bytes for the given name.
func getPrivateKey(c *CryptoContext, name string) ([]byte, error) {
	id, err := c.GetUUID(name)
	if err != nil {
		return nil, err
	}

	pph, _ := id.MarshalBinary()
	privKeyBytes, err := c.Keystore.Get(id.String(), pph)
	if err != nil {
		return nil, err
	}
	return privKeyBytes, nil
}

//Creates a new protocol context for a UPP creator (privkey is passed, pubkey is calculated)
func newProtocolContextSigner(Name string, UUID string, PrivKey string, LastSignature string) (*Protocol, error) {
	context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
	protocol := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	//Load reference data into context
	err := setProtocolContext(protocol, Name, UUID, PrivKey, "", LastSignature)
	return protocol, err
}

//Creates a new protocol context for a UPP verifier (only pubkey is needed)
func newProtocolContextVerifier(Name string, UUID string, PubKey string) (*Protocol, error) {
	context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
	protocol := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	//Load reference data into context
	err := setProtocolContext(protocol, Name, UUID, "", PubKey, "")
	return protocol, err
}

//Sets the passed protocol context to the passed values (name, UUID, private Key, last signature), passed as hex strings
//If a value is an empty string ("") it will not be set. If privkey is given, pubkey will be calculated, but
//directly overwritten if an explicit pubkey is passed in
func setProtocolContext(p *Protocol, Name string, UUID string, PrivKey string, PubKey string, LastSignature string) error {
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
		err = p.Crypto.SetKey(Name, id, privBytes)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error setting private key bytes: %v,", err)
		}
	}

	if PubKey != "" {
		//Catch errors
		if UUID == "" {
			return fmt.Errorf("Need UUID to set public key")
		}
		if Name == "" {
			return fmt.Errorf("Need name to set public key")
		}
		//Set public key (public key will automatically be calculated and set)
		pubBytes, err := hex.DecodeString(PubKey)
		if err != nil {
			return fmt.Errorf("setProtocolContext: Error decoding public key string: : %v, string was: %v", err, PubKey)
		}
		err = p.Crypto.SetPublicKey(Name, id, pubBytes)
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
		p.Signatures[id] = lastSigBytes
	}

	return nil
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
