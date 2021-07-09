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

package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestDecodeArrayToStruct decodes a 'Chained' type UPP and checks expected UUID
// and payload/hash data (currently no signature verification tests)
func TestDecodeArrayToStruct(t *testing.T) {

	var tests = []struct {
		testName        string
		inputUPP        string
		expectedUUID    string
		expectedPayload string
	}{
		{
			"ChainedUPP-32BytesPayload-Packet1",
			"9623c4106eac4d0b16e645088c4622e7451ea5a1c440855d94b0ec9c7bcd21149f2044f8f93a6d83dea968ed96c18e02c11c2fe3a04e75a84f3d73adaeb1a0b975e70c5d21a22fb0db8ea6473516210b01404862e92400c420397edf2cf58afb187156d7c4ade27330a92ecf5c653aeb48e106c7f41d926360c440c3456908c392342f34df464f48fc7a44fe2e93d56f097b173629d4d891b1c8542a5237fe2c69310d4462adcb642d4da44ca84629dfa980805057e0642069c96b",
			"6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			"397edf2cf58afb187156d7c4ade27330a92ecf5c653aeb48e106c7f41d926360",
		},
		{
			"ChainedUPP-32BytesPayload-Packet2",
			"9623c4106eac4d0b16e645088c4622e7451ea5a1c4406beb37362b68e6afe66eb33b7ed8d2a5a059e6ca4f627923faa35d2ded50e69a75733b8f006ac8198b67e22ae0489d8d314b16cf59f60f4cb060b84d398d8c8700c4201bb891f6f764cd8293d0c9ceeffc85da0be801a6e7943d328300397edf2cf58ac440c436a0e8ca003d849e1e3a8ca756cf56d6a0599f399f58d8cdbee813ce340cd3bd27ec509b15d5dffeef6b2792f666cf4ecbe8a8e5c58806983fef7ecbaa7182",
			"6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			"1bb891f6f764cd8293d0c9ceeffc85da0be801a6e7943d328300397edf2cf58a",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			//Try to decode chained UPP
			bytesUPP, err := hex.DecodeString(currTest.inputUPP)
			if err != nil {
				t.Fatalf("Error decoding expected input UPP string: %v, string was: %v", err, currTest.inputUPP)
			}
			o, err := Decode(bytesUPP)
			if err != nil {
				t.Errorf("upp can't be decoded: %v", err)
			}
			//Create/cast chained UPP data
			c := o.(*ChainedUPP) //TODO:extend test for other UPP types than 'chained'
			//Check decoded UUID
			if uuid.MustParse(currTest.expectedUUID) != c.Uuid {
				t.Errorf("uuid does not match:\nexpected: %v\ngot:      %v", currTest.expectedUUID, c.Uuid)
			}
			//Check decoded payload/hash
			expectedPayloadBytes, err := hex.DecodeString(currTest.expectedPayload)
			if err != nil {
				t.Fatalf("Error decoding expected payload string: %v, string was: %v", err, currTest.expectedPayload)
			}
			if !(bytes.Equal(expectedPayloadBytes, c.Payload)) {
				t.Errorf("Decoded hash/payload does not match:\nexpected: %x\ngot:      %x", expectedPayloadBytes, c.Payload)
			}
		})
	}
}

func TestGetLastSignatureNOTRDY(t *testing.T) {
	t.Error("GetLastSignature() not implemented")
}

func TestSetLastSignatureNOTRDY(t *testing.T) {
	t.Error("SetLastSignature() not implemented")
}

func TestResetLastSignatureNOTRDY(t *testing.T) {
	t.Error("ResetLastSignature() not implemented")
}

//TestSignHashFails tests the cases where the SignHash function must return an error
//it tests the defined inputs for each of the protocols defined in protocolsToTest(per case)
func TestSignHash_Fails(t *testing.T) {
	var tests = []struct {
		testName             string
		UUIDForContext       string
		privateKeyForContext string
		lastSigForContext    string
		UUIDForSign          string
		hashForSign          string
		protocolsToTest      []ProtocolVersion
	}{
		{
			testName:             "NameNotPresent",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    "",
			UUIDForSign:          "12345678-1234-1234-1234-123456789013",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "ContextNotInitializedNilUUID",
			UUIDForContext:       "00000000-0000-0000-0000-000000000000",
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          "00000000-0000-0000-0000-000000000000",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "NilUUID",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          "00000000-0000-0000-0000-000000000000",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "UUIDAndPrivKeyNotSet",
			UUIDForContext:       "00000000-0000-0000-0000-000000000000",
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          defaultUUID,
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "PrivkeyNotSet",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          defaultUUID,
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "EmptyHash",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          defaultUUID,
			hashForSign:          "",
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "33ByteHash",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          defaultUUID,
			hashForSign:          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "31ByteHash",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          defaultUUID,
			hashForSign:          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Run each test for each protocol that should be tested
		for _, currProtocolToTest := range currTest.protocolsToTest {
			//Create identifier to append to test name
			protocolTypeString := fmt.Sprintf("(ProtocolType=%v)", currProtocolToTest)
			t.Run(currTest.testName+protocolTypeString, func(t *testing.T) {
				asserter := assert.New(t)
				requirer := require.New(t)

				//Create new protocol context
				protocol, err := newProtocolContextSigner(currTest.UUIDForContext, currTest.privateKeyForContext, currTest.lastSigForContext)
				requirer.NoError(err, "Can't continue with test: Creating protocol context failed")

				//Check created UPP (data/structure only, signature is checked later)
				hashBytes, err := hex.DecodeString(currTest.hashForSign)
				requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)

				//Call SignHash() and assert error
				_, err = protocol.SignHash(uuid.MustParse(currTest.UUIDForSign), hashBytes, currProtocolToTest)
				asserter.Error(err, "SignHash() did not return an error for invalid input")

				//remove keys from HSM again if this is a pkcs 11 test
				if *pkcs11CryptoTests {
					requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(currTest.UUIDForContext)))
				}
				//Close Protocol
				requirer.NoError(protocol.Close())
			})
		}
	}
}

//TestSignHash_RandomInput tests if SignHash can correctly create UPPs
// for a random input hash for the signed and chained protocol type
func TestSignHash_RandomInput(t *testing.T) {
	const numberOfTests = 1000
	const nrOfChainedUpps = 3

	inputHash := make([]byte, 32)

	asserter := assert.New(t)
	requirer := require.New(t)

	//Create new protocol context, we use this context for all created UPPs without resetting it
	protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
	requirer.NoError(err, "Creating protocol context failed")

	lastChainSig := defaultLastSig
	//test the random input
	for i := 0; i < numberOfTests; i++ {
		//generate new input
		_, err := rand.Read(inputHash)
		requirer.NoError(err, "Could not generate random hash")

		//Create 'Signed' type UPP with hash
		createdSignedUpp, err := protocol.SignHash(uuid.MustParse(defaultUUID), inputHash[:], Signed)
		requirer.NoErrorf(err, "Protocol.SignHash() failed for Signed type UPP with input hash %v", hex.EncodeToString(inputHash))

		//Check created Signed UPP
		expectedPayloadString := hex.EncodeToString(inputHash[:])
		err = checkSignedUPP(t, createdSignedUpp, expectedPayloadString, defaultPub)
		asserter.NoError(err, "UPP check failed for Signed type UPP with input hash %v", hex.EncodeToString(inputHash))

		//Create multiple chained UPPs
		createdChainedUpps := make([][]byte, nrOfChainedUpps)
		expectedPayloads := make([]string, nrOfChainedUpps)
		for currUppIndex := range createdChainedUpps {
			createdChainedUpps[currUppIndex], err = protocol.SignHash(uuid.MustParse(defaultUUID), inputHash[:], Chained)
			asserter.NoErrorf(err, "SignHash() could not create Chained type UPP for index %v", currUppIndex)
			expectedPayloads[currUppIndex] = hex.EncodeToString(inputHash[:]) //build expected payload array for checking later
		}

		//Check the created UPPs
		err = checkChainedUPPs(t, createdChainedUpps, expectedPayloads, lastChainSig, defaultPub)
		asserter.NoError(err, "UPP check failed for Chained type UPPs with input hash %v", hex.EncodeToString(inputHash))

		//save the last Signature of chain for check in next round TODO: get this using a library function when available, remove sig length magic number
		lastChainUpp := createdChainedUpps[nrOfChainedUpps-1]
		lastChainSig = hex.EncodeToString(lastChainUpp[len(lastChainUpp)-64:])
	}

	//Remove keys from HSM again if this is a pkcs 11 test
	if *pkcs11CryptoTests {
		requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
	}

	//Close Protocol
	requirer.NoError(protocol.Close())
}

//TestSignData_Fails tests the cases where SignData() function must return an error
func TestSignData_Fails(t *testing.T) {
	var tests = []struct {
		testName             string
		UUIDForContext       string
		privateKeyForContext string
		lastSigForContext    string
		UUIDForSign          string
		dataForSign          string
		protocolsToTest      []ProtocolVersion
	}{
		{
			testName:             "emptyData",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          defaultUUID,
			dataForSign:          "",
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "NameNotPresent",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    "",
			UUIDForSign:          "12345678-1234-1234-1234-123456789013",
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "ContextNotInitializedEmptyName",
			UUIDForContext:       "00000000-0000-0000-0000-000000000000",
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          "00000000-0000-0000-0000-000000000000",
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "ContextNotInitializedNonEmptyName",
			UUIDForContext:       "00000000-0000-0000-0000-000000000000",
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "EmptyName",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			UUIDForSign:          "00000000-0000-0000-0000-000000000000",
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "PrivKeyNotSet",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          defaultUUID,
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
		{
			testName:             "PrivkeyNotSet",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: "",
			lastSigForContext:    "",
			UUIDForSign:          defaultUUID,
			dataForSign:          defaultInputData,
			protocolsToTest:      []ProtocolVersion{Signed, Chained},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Run each test for each protocol that should be tested
		for _, currProtocolToTest := range currTest.protocolsToTest {
			//Create identifier to append to test name
			protocolTypeString := fmt.Sprintf("(ProtocolType=%v)", currProtocolToTest)
			t.Run(currTest.testName+protocolTypeString, func(t *testing.T) {
				asserter := assert.New(t)
				requirer := require.New(t)

				//Create new protocol context
				protocol, err := newProtocolContextSigner(currTest.UUIDForContext, currTest.privateKeyForContext, currTest.lastSigForContext)
				requirer.NoError(err, "Can't continue with test: Creating protocol context failed")

				//Decode test data from hex string
				dataBytes, err := hex.DecodeString(currTest.dataForSign)
				requirer.NoErrorf(err, "Test configuration string (dataForSign) can't be decoded.\nString was: %v", currTest.dataForSign)

				//Call SignData() and assert error
				_, err = protocol.SignData(uuid.MustParse(currTest.UUIDForSign), dataBytes, currProtocolToTest)
				asserter.Error(err, "SignData() did not return an error for invalid input")

				//Remove keys from HSM again if this is a pkcs 11 test
				if *pkcs11CryptoTests {
					requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(currTest.UUIDForContext)))
				}

				//Close Protocol
				requirer.NoError(protocol.Close())
			})
		}
	}
}

//TestSignData_DataInputLength checks if UPPs can be created correctly with data input lengths from 1 to maxDataSizetoTest.
//Signed and chained UPPs are created for all data input sizes and correct signature, payload/expected hash and chain (for chained)
//are checked. This should help in catching errors that only occur for certain input lengths e.g. buffer and len() calculation issues.
func TestSignData_DataInputLength(t *testing.T) {
	const (
		maxDataSizetoTest = 2 * 1024 //in Byte, be aware that test time is on the order of (Size!)
		nrOfChainedUpps   = 3
	)

	//Tests for signed and chained type
	for currentDataSize := 1; currentDataSize <= maxDataSizetoTest; currentDataSize++ {
		//Generate pseudorandom data. As the data size is the same as the test run number we use it as seed.
		//This way the data is reproducible but not simply only 0xff.. or 0x00.. and hopefully we catch a
		//few more errors in this way
		dataBytes := deterministicPseudoRandomBytes(int32(currentDataSize), currentDataSize)
		//The hashing algorith might need to be adjusted if different cryptos are implemented
		expectedDataHash := sha256.Sum256(dataBytes)

		currTestName := "DataSize=" + fmt.Sprintf("%v", currentDataSize)

		//run test for signed type
		t.Run(currTestName+"-SignedType", func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new protocol context
			protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
			requirer.NoError(err, "Can't continue with test: Creating protocol context failed")

			//Call SignData() to create UPP
			createdSignedUpp, err := protocol.SignData(uuid.MustParse(defaultUUID), dataBytes, Signed)
			asserter.NoError(err, "SignData() could not create Signed type UPP")

			//Check created UPP
			expectedPayloadString := hex.EncodeToString(expectedDataHash[:])
			asserter.NoError(checkSignedUPP(t, createdSignedUpp, expectedPayloadString, defaultPub))

			//Remove keys from HSM again if this is a pkcs 11 test
			if *pkcs11CryptoTests {
				requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
			}

			//Close Protocol
			requirer.NoError(protocol.Close())
		})

		//run test for chained type
		t.Run(currTestName+"-ChainedType", func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new protocol context
			protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
			requirer.NoError(err, "Can't continue with test: Creating protocol context failed")

			//Call SignData() to create multiple chained UPPs
			createdChainedUpps := make([][]byte, nrOfChainedUpps)
			expectedPayloads := make([]string, nrOfChainedUpps)
			for currUppIndex := range createdChainedUpps {
				createdChainedUpps[currUppIndex], err = protocol.SignData(uuid.MustParse(defaultUUID), dataBytes, Chained)
				asserter.NoErrorf(err, "SignData() could not create Chained type UPP number %v", currUppIndex)
				expectedPayloads[currUppIndex] = hex.EncodeToString(expectedDataHash[:]) //build expected payload array for checking later
			}

			//Check the created UPPs
			asserter.NoError(checkChainedUPPs(t, createdChainedUpps, expectedPayloads, defaultLastSig, defaultPub))

			//Remove keys from HSM again if this is a pkcs 11 test
			if *pkcs11CryptoTests {
				requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
			}

			//Close Protocol
			requirer.NoError(protocol.Close())
		})

	}
}

//TestSignData_RandomInput tests if SignData can correctly create UPPs
// for random input data for the signed and chained protocol type
//TODO: add randomization of parameters?
func TestSignData_RandomInput(t *testing.T) {
	const numberOfTests = 1000
	const nrOfChainedUpps = 3
	const dataLength = defaultDataSize

	inputData := make([]byte, dataLength)

	asserter := assert.New(t)
	requirer := require.New(t)

	//Create new protocol context, we use this context for all created UPPs without resetting it
	protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
	requirer.NoError(err, "Creating protocol context failed")

	lastChainSig := defaultLastSig
	//test the random input
	for i := 0; i < numberOfTests; i++ {
		//generate new input
		_, err := rand.Read(inputData)
		requirer.NoError(err, "Could not generate random data")
		//Calculate hash, TODO: Make this dependent on crypto if more than one crypto is implemented
		inputDataHash := sha256.Sum256(inputData)

		//Create 'Signed' type UPP with data
		createdSignedUpp, err := protocol.SignData(uuid.MustParse(defaultUUID), inputData[:], Signed)
		requirer.NoErrorf(err, "Protocol.SignData() failed for Signed type UPP with input data %v", hex.EncodeToString(inputData))

		//Check created Signed UPP
		expectedPayloadString := hex.EncodeToString(inputDataHash[:])
		err = checkSignedUPP(t, createdSignedUpp, expectedPayloadString, defaultPub)
		asserter.NoError(err, "UPP check failed for Signed type UPP with input data %v", hex.EncodeToString(inputData))

		//Create multiple chained UPPs
		createdChainedUpps := make([][]byte, nrOfChainedUpps)
		expectedPayloads := make([]string, nrOfChainedUpps)
		for currUppIndex := range createdChainedUpps {
			createdChainedUpps[currUppIndex], err = protocol.SignData(uuid.MustParse(defaultUUID), inputData[:], Chained)
			asserter.NoErrorf(err, "SignData() could not create Chained type UPP for index %v", currUppIndex)
			expectedPayloads[currUppIndex] = hex.EncodeToString(inputDataHash[:]) //build expected payload array for checking later
		}

		//Check the created UPPs
		err = checkChainedUPPs(t, createdChainedUpps, expectedPayloads, lastChainSig, defaultPub)
		asserter.NoError(err, "UPP check failed for Chained type UPPs with input data %v", hex.EncodeToString(inputData))

		//save the last Signature of chain for check in next round TODO: get this using a library function when available, remove sig length magic number
		lastChainUpp := createdChainedUpps[nrOfChainedUpps-1]
		lastChainSig = hex.EncodeToString(lastChainUpp[len(lastChainUpp)-64:])
	}

	//Remove keys from HSM again if this is a pkcs 11 test
	if *pkcs11CryptoTests {
		requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
	}

	//Close Protocol
	requirer.NoError(protocol.Close())
}

//TestSignData_Signed tests 'Signed' type UPP creation from given user data. The created encoded UPP
//data is compared to the expected values, the signature is also checked. As it's non-deterministic,
// signature in expected UPPs are ignored, instead a proper verification with the public key is performed
func TestSignData_SignedType(t *testing.T) {
	var tests = []struct {
		testName    string
		privateKey  string
		publicKey   string
		deviceUUID  string
		userData    string //this is not a hash but the data that the user wants to be sealed/ubirchified
		expectedUPP string //signature contained in expected UPP is only placeholder, instead, actual created signature is checked
	}{
		{
			testName:    "Data='1'",
			privateKey:  defaultPriv,
			publicKey:   defaultPub,
			deviceUUID:  defaultUUID,
			userData:    "31", //equals the character "1" string
			expectedUPP: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			testName:    "Data='Hello World!'",
			privateKey:  defaultPriv,
			publicKey:   defaultPub,
			deviceUUID:  defaultUUID,
			userData:    "48656c6c6f20576f726c6421", //"Hello World!"
			expectedUPP: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new protocol context
			protocol, err := newProtocolContextSigner(currTest.deviceUUID, currTest.privateKey, defaultLastSig)
			requirer.NoError(err, "Creating protocol context failed")

			//Create 'Signed' type UPP with user data
			userDataBytes, err := hex.DecodeString(currTest.userData)
			requirer.NoErrorf(err, "Test configuration string (input data) can't be decoded.\nString was: %v", currTest.userData)
			createdUpp, err := protocol.SignData(uuid.MustParse(defaultUUID), userDataBytes, Signed)
			requirer.NoError(err, "Protocol.SignData() failed")

			//Check created UPP (data/structure only, signature is checked later)
			expectedUPPBytes, err := hex.DecodeString(currTest.expectedUPP)
			requirer.NoErrorf(err, "Test configuration string (expected UPP) can't be decoded.\nString was: %v", currTest.expectedUPP)

			createdUppNoSignature := createdUpp[:len(createdUpp)-64]
			expectedUppNoSignature := expectedUPPBytes[:len(expectedUPPBytes)-64]
			asserter.Equal(createdUppNoSignature, expectedUppNoSignature, "Created UPP data is not as expected")

			//Check signature
			pubkeyBytes, err := hex.DecodeString(currTest.publicKey)
			requirer.NoErrorf(err, "Test configuration string (pubkey) can't be decoded.\nString was: %v", currTest.publicKey)

			verifyOK, err := verifyUPPSignature(t, createdUpp, pubkeyBytes)
			requirer.NoError(err, "Signature verification could not be performed due to errors")
			asserter.True(verifyOK, "Signature is not OK")

			//Remove keys from HSM again if this is a pkcs 11 test
			if *pkcs11CryptoTests {
				requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(currTest.deviceUUID)))
			}

			//Close Protocol
			requirer.NoError(protocol.Close())
		})
	}
}

//TestSignData_Chained tests 'Chained' type UPP creation across multiple chained packets. The created
// encoded UPP data (without the signature, as its non-deterministic) is compared to the expected
// values. Each UPP signature and the signature chain are also verified.
func TestSignData_ChainedType(t *testing.T) {
	var tests = []struct {
		testName            string
		privateKey          string
		publicKey           string
		deviceUUID          string
		lastSignature       string   // last signature before first packet in array of expected packets
		UserDataInputs      []string // array of user data input (not a hash) for hashing and UPP creation
		expectedChainedUpps []string //signature in expected UPPs is only placeholder, instead, actual created signature is checked
	}{
		{
			testName:      "dontSetLastSignature",
			privateKey:    defaultPriv,
			publicKey:     defaultPub,
			deviceUUID:    defaultUUID,
			lastSignature: "", //""=don't set signature
			UserDataInputs: []string{
				"01",
				"02",
				"03",
			},
			expectedChainedUpps: []string{
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
		},
		{
			testName:      "SpecificPrivAndPubKey",
			privateKey:    "10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559",
			publicKey:     "92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a",
			deviceUUID:    defaultUUID,
			lastSignature: defaultLastSig,
			UserDataInputs: []string{
				"01",
				"02",
				"03",
			},
			expectedChainedUpps: []string{
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new protocol context
			protocol, err := newProtocolContextSigner(currTest.deviceUUID, currTest.privateKey, currTest.lastSignature)
			requirer.NoError(err, "Creating protocol context failed")

			requirer.Equal(len(currTest.UserDataInputs), len(currTest.expectedChainedUpps), "Number of input data sets does not match number of expected UPPs")

			createdUpps := make([][]byte, len(currTest.UserDataInputs))
			//Loop over input data and create all UPP packets for this test
			for currInputIndex, currInputData := range currTest.UserDataInputs {
				//Create 'chained' type UPP with user data
				userDataBytes, err := hex.DecodeString(currInputData)
				requirer.NoErrorf(err, "Test configuration string (input data) can't be decoded for input %v. String was: %v", currInputIndex, currInputData)
				createdUppData, err := protocol.SignData(uuid.MustParse(defaultUUID), userDataBytes, Chained)
				requirer.NoErrorf(err, "Protocol.SignData() failed for input data at index %v", currInputIndex)
				//Save UPP into array of all created UPPs
				createdUpps[currInputIndex] = createdUppData
			}

			//Remove keys from HSM again if this is a pkcs 11 test
			if *pkcs11CryptoTests {
				requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(currTest.deviceUUID)))
			}

			//Close Protocol
			requirer.NoError(protocol.Close())

			//Check all created UPPs (data/structure only, signature and lastSignature are ignored and are checked later)
			for currCreatedUppIndex, currCreatedUppData := range createdUpps {
				//Decode expected UPP data
				expectedUppString := currTest.expectedChainedUpps[currCreatedUppIndex]
				expectedUPPBytes, err := hex.DecodeString(expectedUppString)
				requirer.NoErrorf(err, "Test configuration string (expected UPP) can't be decoded for input %v.\nString was: %v", currCreatedUppIndex, expectedUppString)

				//Overwrite lastSignature and signature with zeroes (these are checked separately later)
				//we need to copy into a new slice for this, so we don't modify the array with the created UPPs
				//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
				//create new slicesby appending to an empty slice all source slice elements
				createdUppNoSignatures := append([]byte{}, currCreatedUppData...)
				expectedUppNoSignatures := append([]byte{}, expectedUPPBytes...)
				//zeroize signature
				copy(createdUppNoSignatures[len(createdUppNoSignatures)-64:], make([]byte, 64))
				copy(expectedUppNoSignatures[len(expectedUppNoSignatures)-64:], make([]byte, 64))
				//zeroize lastSignature
				copy(createdUppNoSignatures[22:22+64], make([]byte, 64))
				copy(expectedUppNoSignatures[22:22+64], make([]byte, 64))

				//Do the check
				asserter.Equalf(createdUppNoSignatures, expectedUppNoSignatures, "Created UPP data is not as expected for UPP at index %v", currCreatedUppIndex)
			}

			//check chaining of created UPPs
			var lastSignatureBytes []byte
			if currTest.lastSignature == "" { //check if no signature was set
				lastSignatureBytes = make([]byte, 64) //in that case, chain should start with 00...00 in lastSignature field
			} else { //else decode last signature string
				lastSignatureBytes, err = hex.DecodeString(currTest.lastSignature)
				requirer.NoErrorf(err, "Test configuration string (last Signature) can't be decoded . String was: %v", currTest.lastSignature)
			}
			err = verifyUPPChain(t, createdUpps, lastSignatureBytes)
			asserter.NoError(err, "Chain verification failed")

			//Check signatures of the created UPPs
			for currCreatedUppIndex, currCreatedUppData := range createdUpps {
				pubkeyBytes, err := hex.DecodeString(currTest.publicKey)
				requirer.NoErrorf(err, "Test configuration string (pubkey) can't be decoded for input %v. String was: %v", currCreatedUppIndex, currTest.publicKey)

				verifyOK, err := verifyUPPSignature(t, currCreatedUppData, pubkeyBytes)
				requirer.NoErrorf(err, "Signature verification could not be performed due to errors for created UPP at index %v", currCreatedUppIndex)
				asserter.Truef(verifyOK, "Signature is not OK for created UPP at index %v", currCreatedUppIndex)
			}
		})
	}
}

//TestSignData_CorruptContext tests the cases where SignData() function must return an error because of the
//context (or by extension the keystore) are corrupt with otherwise correct parameters. It uses a table with
// explicitly defined corrupt contexts/keystores.
func TestSignData_CorruptContext(t *testing.T) {
	//Generate some standard structs to use in tests table
	//empty
	emptyKeystore := NewEncryptedKeystore([]byte(defaultSecret))
	// for tests with nil/empty last signature (written for bug UP-1693)
	protocolLastSigNil, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
	require.NoError(t, err, "Could not create protocolLastSigNil")
	protocolLastSigNil.signatures[uuid.MustParse(defaultUUID)] = nil
	// If this is a pkcs#11 HSM test, remove the previously set keypair, as all crypto interfaces share the same HSM and else
	// we will get an error because the Key already exists when we setup protocolLastSigEmpty next.
	if *pkcs11CryptoTests {
		require.NoError(t, pkcs11DeleteKeypair(protocolLastSigNil.Crypto, uuid.MustParse(defaultUUID)))
	}
	protocolLastSigEmpty, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
	require.NoError(t, err, "Could not create protocolLastSigEmpty")
	protocolLastSigEmpty.signatures[uuid.MustParse(defaultUUID)] = []byte{}

	//test cases
	var tests = []struct {
		testName           string
		testProtocolStruct *ExtendedProtocol
		UUIDForSign        string //device name to use in call to SignData(), should match context/protocol data (if desired)
		protocolsToTest    []ProtocolVersion
	}{
		{
			testName: "EmptyContext", //no keys, no devices in Names list
			testProtocolStruct: NewExtendedProtocol(&ECDSACryptoContext{
				Keystore: emptyKeystore,
			}, map[uuid.UUID][]byte{}),
			UUIDForSign:     "00000000-0000-0000-0000-000000000000",
			protocolsToTest: []ProtocolVersion{Signed, Chained},
		},
		{
			testName: "NameOkKeystoreEmpty", //Device is in list of devices but no key is in the Keystore (written for bug UP-1693)
			testProtocolStruct: NewExtendedProtocol(&ECDSACryptoContext{
				Keystore: emptyKeystore,
			}, map[uuid.UUID][]byte{}),
			UUIDForSign:     defaultUUID,
			protocolsToTest: []ProtocolVersion{Signed, Chained},
		},
		{
			testName:           "LastSignatureNil", //evrything OK but last signature is present but nil (written for bug UP-1693)
			testProtocolStruct: protocolLastSigNil,
			UUIDForSign:        defaultUUID,
			protocolsToTest:    []ProtocolVersion{Chained}, //only relevant for chained
		},
		{
			testName:           "LastSignatureEmpty", //evrything OK but last signature is present but empty (written for bug UP-1693)
			testProtocolStruct: protocolLastSigEmpty,
			UUIDForSign:        defaultUUID,
			protocolsToTest:    []ProtocolVersion{Chained}, //only relevant for chained
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Run each test for each protocol that should be tested
		for _, currProtocolToTest := range currTest.protocolsToTest {
			//Create identifier to append to test name
			protocolTypeString := fmt.Sprintf("(ProtocolType=%v)", currProtocolToTest)
			t.Run(currTest.testName+protocolTypeString, func(t *testing.T) {
				asserter := assert.New(t)
				requirer := require.New(t)

				//Load protocol/context/keystore from test data new crypto context
				protocol := currTest.testProtocolStruct

				//Parse default user data string
				userDataBytes, err := hex.DecodeString(defaultInputData)
				requirer.NoErrorf(err, "Test configuration string (defaultInputData) can't be decoded.\nString was: %v", defaultInputData)

				//Call SignData() and assert error
				_, err = protocol.SignData(uuid.MustParse(currTest.UUIDForSign), userDataBytes, currProtocolToTest)
				asserter.Error(err, "SignData() did not return an error for a faulty protocol context")
			})
		}
	}

	//Clean up nil and empty protocols
	//First, remove keys from HSM if this is a pkcs 11 test, we only need to do this for one protocol as the HSM is
	// shared among contexts.
	if *pkcs11CryptoTests {
		require.NoError(t, pkcs11DeleteKeypair(protocolLastSigNil.Crypto, uuid.MustParse(defaultUUID)))
	}
	//Then close the protocols themselves
	require.NoError(t, protocolLastSigNil.Close())
	if !*pkcs11CryptoTests { //for pkcs#11 tests, the underlying hardware/library is shared, so the above close operation has already closed everything
		require.NoError(t, protocolLastSigEmpty.Close())
	}
}

//TestECDSALibrary in its current state only tests if the ECDSA library behaves as expected
func TestECDSALibrary(t *testing.T) {
	asserter := assert.New(t)

	vkb, _ := base64.StdEncoding.DecodeString("o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==")
	hsh, _ := base64.StdEncoding.DecodeString("T2v511D0Upfr7Vl0DY5xnganDXlUCILCfZvetExHgzQ=")
	sig, _ := base64.StdEncoding.DecodeString("WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AGng==")

	x := &big.Int{}
	x.SetBytes(vkb[0:32])
	y := &big.Int{}
	y.SetBytes(vkb[32:64])

	vk := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])

	asserter.True(ecdsa.Verify(&vk, hsh, r, s), "ecdsa.Verify() failed to verify known-good signature")
}

// TestProtocol_Verify verifies UPP packages for different configurations.
//		Tests, which shall pass, have the attribute signatureVerifiable = true,
//		Tests, which shall return an error, have the attribute signatureVerifiable = false
func TestProtocol_Verify(t *testing.T) {
	var tests = []struct {
		testName            string
		UUIDForProtocol     string
		UUIDForVerify       string
		pubKey              string
		input               string
		signatureVerifiable bool
		throwsError         bool
	}{
		{
			testName:            "signed UPP correct '1'",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			signatureVerifiable: true,
			throwsError:         false,
		},
		{
			testName:            "signed UPP correct 'Hello world'",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359685bc4ac06103234fa9b94a1e2f94b338405aa520d5a4e03734d85e43abe5e88f57d2f74e2526b30356c47a6e239dc4cc694f5f9c19d1f",
			signatureVerifiable: true,
			throwsError:         false,
		},
		{
			testName:            "chained UPP correct without last signature",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a",
			signatureVerifiable: true,
			throwsError:         false,
		},
		{
			testName:            "chained UPP correct with last signature",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			signatureVerifiable: true,
			throwsError:         false,
		},
		{
			testName:            "chained wrong name for protocol",
			UUIDForProtocol:     "12345678-1234-1234-1234-123456789012",
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "chained wrong name for Verify",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       "12345678-1234-1234-1234-123456789012",
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "chained empty name for Verify",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       "00000000-0000-0000-0000-000000000000",
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "chained empty data",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "chained wrong signature",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdd",
			signatureVerifiable: false,
			throwsError:         false,
		},
		{
			testName:            "signed wrong signature",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359685bc4ac06103234fa9b94a1e2f94b338405aa520d5a4e03734d85e43abe5e88f57d2f74e2526b30356c47a6e239dc4cc694f5fab19d1f",
			signatureVerifiable: false,
			throwsError:         false,
		},
		{
			testName:            "no data",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "c4400b4b7ac56f571be787664d839b02e9dc4114145f69f0e7b644222db9e97b3d273e6a0a5219473b57d0afee5c4254c8d9ac31c2ccb080d2c2a9363df7459f0774",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "signed data too short (66 Byte)",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359",
			signatureVerifiable: false,
			throwsError:         true,
		},
		{
			testName:            "signed data too short(65 Byte)",
			UUIDForProtocol:     defaultUUID,
			UUIDForVerify:       defaultUUID,
			pubKey:              defaultPub,
			input:               "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359",
			signatureVerifiable: false,
			throwsError:         true,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			requirer := require.New(t)
			asserter := assert.New(t)

			// Create new context
			protocol, err := newProtocolContextVerifier(currTest.UUIDForProtocol, currTest.pubKey)
			requirer.NoError(err, "Creating protocol context failed: %v", err)

			// convert test input string to bytes
			inputBytes, err := hex.DecodeString(currTest.input)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.input)

			// verify test input
			verified, err := protocol.Verify(uuid.MustParse(currTest.UUIDForVerify), inputBytes)
			if currTest.signatureVerifiable {
				asserter.Truef(verified, "test input was not verifiable. Input was %s", currTest.input)
			} else {
				asserter.Falsef(verified, "test input was verifiable. Input was %s", currTest.input)
			}
			if currTest.throwsError {
				asserter.Errorf(err, "protocol.Verify() returned  no error")
			} else {
				asserter.NoErrorf(err, "protocol.Verify() returned error: %v", err)
			}

			//Remove keys from HSM again if this is a pkcs 11 test
			if *pkcs11CryptoTests {
				requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(currTest.UUIDForProtocol)))
			}

			//Close Protocol
			requirer.NoError(protocol.Close())
		})
	}
}

//TestProtocol_SignVerifyLoop tests if a loop of creating and verifying an UPP with the lib
//functions works as expected (SignData and Verify). This mainly tests if packet creation and
//verification/unpacking is consistent within the library. This is tested with random data
//and random parameters to catch errors with certain parameters. Tests are run for both signed
//and chained type. Chaining is not checked as the library does not provide such a function. The
//chaining is however checked in TestSignData_RandomInput with a test helper function.
//TODO: Add library chain check function here when/if library is extended to support it
func TestProtocol_SignDataVerifyDecodeLoop(t *testing.T) {
	const numberOfTests = 1000 //total number of tests
	const nrOfUPPsPerTest = 10 //number of chained and signed packets for each test (generated with one set of parameters)
	const dataLength = defaultDataSize

	currData := make([]byte, dataLength)
	currUUIDTypeUUID := uuid.Nil
	currUUID := ""
	privBytes := make([]byte, 32)
	currPriv := ""
	currPub := ""
	lastSigBytes := make([]byte, 64)
	currLastSig := ""

	asserter := assert.New(t)
	requirer := require.New(t)

	//test the random input
	for i := 0; i < numberOfTests; i++ {
		//generate new random parameters
		//UUID
		currUUIDTypeUUID = uuid.New()
		currUUID = currUUIDTypeUUID.String()
		//Privkey
		_, err := rand.Read(privBytes)
		requirer.NoError(err, "Could not generate random data for private key")
		currPriv = hex.EncodeToString(privBytes)
		//Last Signature
		_, err = rand.Read(lastSigBytes)
		requirer.NoError(err, "Could not generate random data for last signature")
		currLastSig = hex.EncodeToString(lastSigBytes)

		//Create new crypto contexts, new one for each round for parameter randomization
		//Signer
		signer, err := newProtocolContextSigner(currUUID, currPriv, currLastSig)
		requirer.NoError(err, "Creating signer protocol context failed")
		//Verifier
		currPubkeyBytes, err := signer.GetPublicKey(uuid.MustParse(currUUID))
		requirer.NoError(err, "Could not get pubkey from signer context")
		currPub = hex.EncodeToString(currPubkeyBytes)
		// If this is a test using the HSM, there is already a public key from the signer in the HSM at this point. We
		// will remove only this public key, which will then be set by the creation of the verifier again.
		if *pkcs11CryptoTests {
			requirer.NoError(signer.Crypto.(*ECDSAPKCS11CryptoContext).pkcs11DeletePublicKey(uuid.MustParse(currUUID)))
		}
		verifier, err := newProtocolContextVerifier(currUUID, currPub)
		requirer.NoError(err, "Creating verifier protocol context failed")

		//create a number of signed and chained type UPPs and verify/decode them with the library
		for currUPPIndex := 0; currUPPIndex < nrOfUPPsPerTest; currUPPIndex++ {
			//TODO: Output parameters as well (Log?), helper function for parameter string?
			//generate new random data
			_, err := rand.Read(currData)
			requirer.NoError(err, "Could not generate random data for input data")
			//Calculate hash for later checking, TODO: Make this dependent on crypto if more than one crypto is implemented
			currDataHash := sha256.Sum256(currData)

			//Create string to use in error messages with all necessary info
			debugInfoString := fmt.Sprintf("Input data: %v\nParameters:\n%v",
				hex.EncodeToString(currData),
				parameterString(currUUID, currPriv, currPub, currLastSig))

			////SIGNED section////
			//Create 'Signed' type UPP with data
			createdSignedUpp, err := signer.SignData(uuid.MustParse(currUUID), currData[:], Signed)
			requirer.NoErrorf(err, "Protocol.SignData() failed for Signed type UPP\n%v", debugInfoString)

			//Check created Signed UPP using the library function: first verify, then decode and check hash/payload
			result, err := verifier.Verify(uuid.MustParse(currUUID), createdSignedUpp)
			asserter.NoError(err, "UPP verify failed with an error for Signed type UPP\n%v", debugInfoString)
			asserter.True(result, "UPP verification returned false for Signed type UPP\n%v", debugInfoString)
			decodedUPP, err := Decode(createdSignedUpp)
			asserter.NoError(err, "UPP decoding failed with an error for Signed type UPP\n%v", debugInfoString)
			//Check payload (and other struct contents)
			asserter.Equal(Signed, decodedUPP.(*SignedUPP).Version, "Signed type Version not as expected\n%v", debugInfoString)
			asserter.Equal(currUUIDTypeUUID, decodedUPP.(*SignedUPP).Uuid, "Signed type UUID not as expected\n%v", debugInfoString)
			asserter.Equal(Hint(0x00), decodedUPP.(*SignedUPP).Hint, "Signed type Hint not as expected\n%v", debugInfoString)
			asserter.Equal(currDataHash[:], decodedUPP.(*SignedUPP).Payload, "Signed type Payload not as expected\n%v", debugInfoString)

			////CHAINED section////
			//Create 'Chained' type UPP with data
			createdChainedUpp, err := signer.SignData(uuid.MustParse(currUUID), currData[:], Chained)
			requirer.NoErrorf(err, "Protocol.SignData() failed for Chained type UPP\n%v", debugInfoString)

			//Check created Chained UPP using the library function: first verify, then decode and check hash/payload
			result, err = verifier.Verify(uuid.MustParse(currUUID), createdChainedUpp)
			asserter.NoError(err, "UPP verify failed with an error for Chained type UPP\n%v", debugInfoString)
			asserter.True(result, "UPP verification returned false for Chained type UPP\n%v", debugInfoString)
			decodedUPP, err = Decode(createdChainedUpp)
			asserter.NoError(err, "UPP decoding failed with an error for Chained type UPP\n%v", debugInfoString)
			//Check payload (and other struct contents)
			asserter.Equal(Chained, decodedUPP.(*ChainedUPP).Version, "Chained type Version not as expected\n%v", debugInfoString)
			asserter.Equal(currUUIDTypeUUID, decodedUPP.(*ChainedUPP).Uuid, "Chained type UUID not as expected\n%v", debugInfoString)
			asserter.Equal(Hint(0x00), decodedUPP.(*ChainedUPP).Hint, "Chained type Hint not as expected\n%v", debugInfoString)
			asserter.Equal(currDataHash[:], decodedUPP.(*ChainedUPP).Payload, "Chained type Payload not as expected\n%v", debugInfoString)
		}

		// Remove keys from HSM again if this is a pkcs 11 test, for a HSM signer and verifier will actually use the
		// same keypair in the HSM as there is only one hardware/simulator, so deleting only the signer keypair should
		// be enough.
		if *pkcs11CryptoTests {
			requirer.NoError(pkcs11DeleteKeypair(signer.Crypto, uuid.MustParse(currUUID)))
		}

		//Close Protocols
		requirer.NoError(signer.Close())
		if !*pkcs11CryptoTests { //for pkcs#11 tests, the underlying hardware/library is shared, so the above close operation has already closed everything
			requirer.NoError(verifier.Close())
		}
	}
}

// TestDecode tests the Decode function of the ubirch package.
// To test invalid input, don't set the `protoType`-attribute of the test-struct (defaults to 0).
// If the input is decoded successfully despite being invalid, the test should fail.
func TestDecode(t *testing.T) {
	var tests = []struct {
		testName      string
		UPP           string
		protoType     ProtocolVersion
		UUID          string
		PrevSignature string
		Hint          Hint
		Payload       string
		Signature     string
	}{
		{
			testName:      "signed UPP",
			UPP:           "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType:     Signed,
			UUID:          defaultUUID,
			PrevSignature: "",
			Hint:          0x00,
			Payload:       "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature:     "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName:      "chained UPP",
			UPP:           "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
			protoType:     Chained,
			UUID:          defaultUUID,
			PrevSignature: "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			Hint:          0x00,
			Payload:       "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature:     "62328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UPP",
			UPP:      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		},
		{
			testName: "incomplete UPP",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcda",
		},
		{
			testName: "empty input",
			UPP:      "",
		},
		{
			testName: "invalid version",
			UPP:      "9600c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (chained UPP with version 0x22)",
			UPP:      "9622c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (signed UPP with version 0x23)",
			UPP:      "9523c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName: "invalid UUID (too long)",
			UPP:      "9623c411666eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (too short)",
			UPP:      "9623c40aac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (string)",
			UPP:      "9623d9203536626439623835366336653461323462663731663261633264653130313833c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (negative fixnum)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fce0c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (uint 16)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fccdffffc4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid signature (uint 64)",
			UPP:      "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bcfbc2a01322c679b96",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			// parse test parameters into correct types
			var id uuid.UUID
			var err error
			if currTest.UUID != "" {
				id, err = uuid.Parse(currTest.UUID)
				requirer.NoErrorf(err, "Parsing UUID from string failed: %v, string was: %v", err, currTest.UUID)
			}

			prevSigBytes, err := hex.DecodeString(currTest.PrevSignature)
			requirer.NoErrorf(err, "Decoding test PrevSignature from string failed: %v, string was: %v", err, currTest.PrevSignature)

			payloadBytes, err := hex.DecodeString(currTest.Payload)
			requirer.NoErrorf(err, "Decoding test Payload from string failed: %v, string was: %v", err, currTest.Payload)

			signatureBytes, err := hex.DecodeString(currTest.Signature)
			requirer.NoErrorf(err, "Decoding test Signature from string failed: %v, string was: %v", err, currTest.Signature)

			uppBytes, err := hex.DecodeString(currTest.UPP)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.UPP)

			// decode test input
			decoded, err := Decode(uppBytes)

			switch currTest.protoType {
			case Signed:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsTypef(&SignedUPP{}, decoded, "signed UPP input was decoded to type %T", decoded)
				requirer.NoErrorf(err, "Decode() returned error: %v", err)
				signed := decoded.(*SignedUPP)

				// check if decoded UPP has expected attributes
				asserter.Equalf(currTest.protoType, signed.Version, "decoded incorrect protocol version")
				asserter.Equalf(id, signed.Uuid, "decoded incorrect uuid")
				asserter.Equalf(currTest.Hint, signed.Hint, "decoded incorrect hint")
				asserter.Equalf(payloadBytes, signed.Payload, "decoded incorrect payload")
				asserter.Equalf(signatureBytes, signed.Signature, "decoded incorrect signature")

			case Chained:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsTypef(&ChainedUPP{}, decoded, "chained UPP input was decoded to type %T", decoded)
				requirer.NoErrorf(err, "Decode() returned error: %v", err)
				chained := decoded.(*ChainedUPP)

				// check if decoded UPP has expected attributes
				asserter.Equalf(currTest.protoType, chained.Version, "decoded incorrect protocol version")
				asserter.Equalf(id, chained.Uuid, "decoded incorrect uuid")
				asserter.Equalf(prevSigBytes, chained.PrevSignature, "decoded incorrect previous signature")
				asserter.Equalf(currTest.Hint, chained.Hint, "decoded incorrect hint")
				asserter.Equalf(payloadBytes, chained.Payload, "decoded incorrect payload")
				asserter.Equalf(signatureBytes, chained.Signature, "decoded incorrect signature")

			default:
				requirer.Nilf(decoded, "invalid input was decoded to UPP. input was: %s", currTest.UPP)
				requirer.Errorf(err, "Decode() did not return error with invalid input")
			}

			if decoded != nil {
				// check interface
				asserter.Equalf(currTest.protoType, decoded.GetVersion(), "interface returned incorrect protocol version")
				asserter.Equalf(id, decoded.GetUuid(), "interface returned incorrect uuid")
				if currTest.protoType == Signed {
					asserter.Nilf(decoded.GetPrevSignature(), "interface returned incorrect prev signature (not nil)")
				} else {
					asserter.Equalf(prevSigBytes, decoded.GetPrevSignature(), "decoded incorrect previous signature")
				}
				asserter.Equalf(currTest.Hint, decoded.GetHint(), "interface returned incorrect hint")
				asserter.Equalf(payloadBytes, decoded.GetPayload(), "interface returned incorrect payload")
				asserter.Equalf(signatureBytes, decoded.GetSignature(), "interface returned incorrect signature")
			}
		})
	}
}

// TestDecodeSigned tests the DecodeSigned function of the ubirch package.
// To test invalid input, don't set the `protoType`-attribute of the test-struct (defaults to 0).
// If the input is decoded successfully despite being invalid, the test should fail.
func TestDecodeSigned(t *testing.T) {
	var tests = []struct {
		testName  string
		UPP       string
		protoType ProtocolVersion
		UUID      string
		Hint      Hint
		Payload   string
		Signature string
	}{
		{
			testName:  "signed UPP",
			UPP:       "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType: Signed,
			UUID:      defaultUUID,
			Hint:      0x00,
			Payload:   "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature: "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName: "chained UPP",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UPP",
			UPP:      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		},
		{
			testName: "incomplete UPP",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcda",
		},
		{
			testName: "empty input",
			UPP:      "",
		},
		{
			testName: "invalid version",
			UPP:      "9600c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (chained UPP with version 0x22)",
			UPP:      "9622c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (signed UPP with version 0x23)",
			UPP:      "9523c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName: "invalid UUID (too long)",
			UPP:      "9623c411666eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (too short)",
			UPP:      "9623c40aac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (string)",
			UPP:      "9623d9203536626439623835366336653461323462663731663261633264653130313833c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (negative fixnum)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fce0c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (uint 16)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fccdffffc4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid signature (uint 64)",
			UPP:      "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bcfbc2a01322c679b96",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			// parse test parameters into correct types
			var id uuid.UUID
			var err error
			if currTest.UUID != "" {
				id, err = uuid.Parse(currTest.UUID)
				requirer.NoErrorf(err, "Parsing UUID from string failed: %v, string was: %v", err, currTest.UUID)
			}

			payloadBytes, err := hex.DecodeString(currTest.Payload)
			requirer.NoErrorf(err, "Decoding test Payload from string failed: %v, string was: %v", err, currTest.Payload)

			signatureBytes, err := hex.DecodeString(currTest.Signature)
			requirer.NoErrorf(err, "Decoding test Signature from string failed: %v, string was: %v", err, currTest.Signature)

			uppBytes, err := hex.DecodeString(currTest.UPP)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.UPP)

			// decode test input
			decoded, err := DecodeSigned(uppBytes)

			switch currTest.protoType {
			case Signed:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsTypef(&SignedUPP{}, decoded, "signed UPP input was decoded to type %T", decoded)
				requirer.NoErrorf(err, "DecodeSigned() returned error: %v", err)

				// check if decoded UPP has expected attributes
				asserter.Equalf(currTest.protoType, decoded.Version, "decoded incorrect protocol version")
				asserter.Equalf(id, decoded.Uuid, "decoded incorrect uuid")
				asserter.Equalf(currTest.Hint, decoded.Hint, "decoded incorrect hint")
				asserter.Equalf(payloadBytes, decoded.Payload, "decoded incorrect payload")
				asserter.Equalf(signatureBytes, decoded.Signature, "decoded incorrect signature")

				// check interface
				asserter.Equalf(currTest.protoType, decoded.GetVersion(), "interface returned incorrect protocol version")
				asserter.Equalf(id, decoded.GetUuid(), "interface returned incorrect uuid")
				asserter.Nilf(decoded.GetPrevSignature(), "interface returned incorrect prev signature (not nil)")
				asserter.Equalf(currTest.Hint, decoded.GetHint(), "interface returned incorrect hint")
				asserter.Equalf(payloadBytes, decoded.GetPayload(), "interface returned incorrect payload")
				asserter.Equalf(signatureBytes, decoded.GetSignature(), "interface returned incorrect signature")

			default:
				requirer.Nilf(decoded, "invalid input was decoded to UPP. input was: %s", currTest.UPP)
				requirer.Errorf(err, "DecodeSigned() did not return error with invalid input")
			}
		})
	}
}

// TestDecodeChained tests the DecodeChained function of the ubirch package.
// To test invalid input, don't set the `protoType`-attribute of the test-struct (defaults to 0).
// If the input is decoded successfully despite being invalid, the test should fail.
func TestDecodeChained(t *testing.T) {
	var tests = []struct {
		testName      string
		UPP           string
		protoType     ProtocolVersion
		UUID          string
		PrevSignature string
		Hint          Hint
		Payload       string
		Signature     string
	}{
		{
			testName:      "chained UPP",
			UPP:           "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
			protoType:     Chained,
			UUID:          defaultUUID,
			PrevSignature: "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			Hint:          0x00,
			Payload:       "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature:     "62328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "signed UPP",
			UPP:      "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName: "invalid UPP",
			UPP:      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		},
		{
			testName: "incomplete UPP",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcda",
		},
		{
			testName: "empty input",
			UPP:      "",
		},
		{
			testName: "invalid version",
			UPP:      "9600c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (chained UPP with version 0x22)",
			UPP:      "9622c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "wrong version (signed UPP with version 0x23)",
			UPP:      "9523c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName: "invalid UUID (too long)",
			UPP:      "9623c411666eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (too short)",
			UPP:      "9623c40aac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UUID (string)",
			UPP:      "9623d9203536626439623835366336653461323462663731663261633264653130313833c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (negative fixnum)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fce0c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid hint (uint 16)",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fccdffffc4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid signature (uint 64)",
			UPP:      "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bcfbc2a01322c679b96",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			// parse test parameters into correct types
			var id uuid.UUID
			var err error
			if currTest.UUID != "" {
				id, err = uuid.Parse(currTest.UUID)
				requirer.NoErrorf(err, "Parsing UUID from string failed: %v, string was: %v", err, currTest.UUID)
			}

			prevSigBytes, err := hex.DecodeString(currTest.PrevSignature)
			requirer.NoErrorf(err, "Decoding test PrevSignature from string failed: %v, string was: %v", err, currTest.PrevSignature)

			payloadBytes, err := hex.DecodeString(currTest.Payload)
			requirer.NoErrorf(err, "Decoding test Payload from string failed: %v, string was: %v", err, currTest.Payload)

			signatureBytes, err := hex.DecodeString(currTest.Signature)
			requirer.NoErrorf(err, "Decoding test Signature from string failed: %v, string was: %v", err, currTest.Signature)

			uppBytes, err := hex.DecodeString(currTest.UPP)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.UPP)

			// decode test input
			decoded, err := DecodeChained(uppBytes)

			switch currTest.protoType {
			case Chained:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsTypef(&ChainedUPP{}, decoded, "chained UPP input was decoded to type %T", decoded)
				requirer.NoErrorf(err, "DecodeChained() returned error: %v", err)

				// check if decoded UPP has expected attributes
				asserter.Equalf(currTest.protoType, decoded.Version, "decoded incorrect protocol version")
				asserter.Equalf(id, decoded.Uuid, "decoded incorrect uuid")
				asserter.Equalf(prevSigBytes, decoded.PrevSignature, "decoded incorrect previous signature")
				asserter.Equalf(currTest.Hint, decoded.Hint, "decoded incorrect hint")
				asserter.Equalf(payloadBytes, decoded.Payload, "decoded incorrect payload")
				asserter.Equalf(signatureBytes, decoded.Signature, "decoded incorrect signature")

				// check interface
				asserter.Equalf(currTest.protoType, decoded.GetVersion(), "interface returned incorrect protocol version")
				asserter.Equalf(id, decoded.GetUuid(), "interface returned incorrect uuid")
				asserter.Equalf(prevSigBytes, decoded.GetPrevSignature(), "decoded incorrect previous signature")
				asserter.Equalf(currTest.Hint, decoded.GetHint(), "interface returned returned incorrect hint")
				asserter.Equalf(payloadBytes, decoded.GetPayload(), "interface returned incorrect payload")
				asserter.Equalf(signatureBytes, decoded.GetSignature(), "interface returned incorrect signature")

			default:
				requirer.Nilf(decoded, "invalid input was decoded to chained UPP. input was: %s", currTest.UPP)
				requirer.Errorf(err, "DecodeChained() did not return error with invalid input")
			}
		})
	}
}

//TestRandomBitFrequency tests random numbers/bits from package "crypto/rand" (which is used in our crypto) to
//detect (serious) problems with the cryptographic random number generation. Implements
//the frequency/monobit test, see NIST Special Publication 800-22 2.1
func TestRandomBitFrequency(t *testing.T) {
	//The p-value to use for the test decision (pCalc < pLimit -> not random), p=0.01 -> 99% confidence,
	//also means 1% of tests fail even with true random source. See NIST Special
	//Publication 800-22 1.1.5
	const pValueLimit = 0.01 //0.01 -> 1% Level

	requirer := require.New(t)

	//Frequency (Monobit) Test
	r := rand.Reader                             //the RNG under test
	nBytes := 256                                //amount of random bytes to be tested
	nBits := nBytes * 8                          //amount of bits in the random data
	randomBytesUnderTest := make([]byte, nBytes) //the random data to be tested for randomness
	_, err := io.ReadFull(r, randomBytesUnderTest)
	requirer.NoError(err, "Generating random bytes failed: %v", err)

	//calculate the frequency of ones and zeros in the random data
	s := 0
	for i := 0; i < nBytes; i++ {
		// get number of one bits (population count)
		ones := bits.OnesCount8(randomBytesUnderTest[i])
		// count +1 for every one bit and -1 for every zero bit
		s += (2 * ones) - 8
	}
	// calculate the test statistic
	sObs := math.Abs(float64(s)) / math.Sqrt(float64(nBits))
	pValueCalc := math.Erfc(sObs / math.Sqrt2)

	//Debug info
	//log.Printf("s: %v", s)
	//log.Printf("Calculated pValue: %v", pValueCalc)
	// for i := 0; i < nBytes-8; {
	// 	log.Printf("%08b%08b%08b%08b%08b%08b%08b%08b\n",
	// 		randomBytesUnderTest[i], randomBytesUnderTest[i+1],
	// 		randomBytesUnderTest[i+2], randomBytesUnderTest[i+3],
	// 		randomBytesUnderTest[i+4], randomBytesUnderTest[i+5],
	// 		randomBytesUnderTest[i+6], randomBytesUnderTest[i+7])
	// 	i += 8
	// }

	//Decision Rule: If the computed P-value is pValueCalc < pValueLimit, then conclude that the sequence is non-random.
	//Otherwise, conclude that the sequence is random.
	requirer.Greater(pValueCalc, pValueLimit, "Random data did not pass Frequency (Monobit) test. (pValueCalc was smaller than pValueLimit)\n"+
		"This means with 99 %% confidence that something is wrong, but in 1 %% of tests there is a false positive.\n"+
		"Random data was :\n%v", randomBytesUnderTest)
}

//TestECDSASignatureChanges tests if the signature of ECDSA changes for the same input using the top level protocol struct.
//If it does not, there is likely a problem with the random number or nonce ('k') generation
//which will allow attackers to calculate the private key from signatures.
//Since only a 'small' number of signatures is checked this will most likely detect only 'total' failures
//in k/nonce generation. See also  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security
//For testing, 'signed' type UPPs are used. Both "new context for each UPP" and "one context across all UPPs" cases are tested
func TestECDSASignatureChanges(t *testing.T) {
	const nrOfSigsToCheck = 1000 //effective number of tests is two time this number as both "new context for each test" and "consistent context" cases are tested

	requirer := require.New(t)

	//Run the test with a fresh context for each test
	signatureMap := make(map[string]bool)
	for currTestNr := 0; currTestNr < nrOfSigsToCheck; currTestNr++ {
		//Create new crypto context (each time)
		protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
		requirer.NoError(err, "Creating protocol context failed")

		//Create 'Signed' type UPP
		createdUpp, err := protocol.SignData(uuid.MustParse(defaultUUID), []byte(defaultInputData), Signed)
		requirer.NoError(err, "Protocol.SignData() failed")

		//Check if signature was already seen, if not remember it
		signature := createdUpp[len(createdUpp)-64:]
		if !signatureMap[hex.EncodeToString(signature)] { //if signature key does not exists in map (standard return value is false)
			signatureMap[hex.EncodeToString(signature)] = true
		} else { //we found a duplicate, raise an error and abort
			t.Fatalf("ECDSA signature collision (duplicate) detected for test %v with fresh context. Private key is leaked in UPPs. Signature was: %v", currTestNr+1, hex.EncodeToString(signature))
		}

		// Remove keys from HSM again if this is a pkcs 11 test
		if *pkcs11CryptoTests {
			requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
		}

		//Close protocol
		requirer.NoError(protocol.Close())
	}

	//Run the test with a continuous context
	signatureMap = make(map[string]bool) //reset signature map
	//Create new crypto context (once)
	protocol, err := newProtocolContextSigner(defaultUUID, defaultPriv, defaultLastSig)
	requirer.NoError(err, "Creating protocol context failed")
	for currTestNr := 0; currTestNr < nrOfSigsToCheck; currTestNr++ {
		//Create 'Signed' type UPP
		createdUpp, err := protocol.SignData(uuid.MustParse(defaultUUID), []byte(defaultInputData), Signed)
		requirer.NoError(err, "Protocol.SignData() failed")

		//Check if signature was already seen, if not remember it
		signature := createdUpp[len(createdUpp)-64:]
		if !signatureMap[hex.EncodeToString(signature)] { //if signature key does not exists in map (standard return value is false)
			signatureMap[hex.EncodeToString(signature)] = true
		} else { //we found a duplicate, raise an error and abort
			t.Fatalf("ECDSA signature collision (duplicate) detected for test %v with continuous context. Private key is leaked in UPPs. Signature was: %v", currTestNr+1, hex.EncodeToString(signature))
		}
	}

	// Remove keys from HSM again if this is a pkcs 11 test
	if *pkcs11CryptoTests {
		requirer.NoError(pkcs11DeleteKeypair(protocol.Crypto, uuid.MustParse(defaultUUID)))
	}

	//Close protocol
	requirer.NoError(protocol.Close())
}

// TestCheckChainLink tests the CheckChainLink function of the ubirch protocol library.
// If the input is decoded successfully despite being invalid, the test should fail.
func TestCheckChainLink(t *testing.T) {
	var tests = []struct {
		testName      string
		prevUPP       string
		subsequentUPP string
		isChained     bool
		returnsError  bool
	}{
		{
			testName:      "valid chain of chained UPPs",
			prevUPP:       "9623c410ba70ad8ba5644e589a3b224ac0f0153fc4404a9d2c0090b362595d8289a118363d31e9db66e18a153056fdd959a76d0ef7c8dedfbcc7cd83d482bc5bd1fd4f6d4fcc083d20f74f5ee497f16c08ea9b6799f200c42055f640b3b97b7fce1422a56b7fa5cfe21092d8837cf300e0428ad050fbde6a52c440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee19",
			subsequentUPP: "9623c410ba70ad8ba5644e589a3b224ac0f0153fc440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee1900c4207a1223d6b5dc387b5a7682be5ad8d478cfd00506b4de2584aaf937ad09df2b44c440ebbc5ab7d1c40fb513bb751fcf954f3f1c9055acf9d456eeba63cd0f86c9f2cf6f52d1618870baad90c5c5b8c30dd5e9969b0cf4d2ab41c1a4fed11ef7803517",
			isChained:     true,
			returnsError:  false,
		},
		{
			testName:      "valid chain with signed UPP",
			prevUPP:       "9522c41056bd9b856c6e4a24bf71f2ac2de1018300c420de3858d827ffd41ff7dcc2b0729951766886081d97f925c75b3ad0fa6c7b14e2c4405819a9df6b4dc176a753a30ccd4b606b37265042876267138426525c12e7a06f92eb2b30dbc1142e7dd73d1376f390671be2790e1e432fce68fc1f28da9ca60a",
			subsequentUPP: "9623c41056bd9b856c6e4a24bf71f2ac2de10183c4405819a9df6b4dc176a753a30ccd4b606b37265042876267138426525c12e7a06f92eb2b30dbc1142e7dd73d1376f390671be2790e1e432fce68fc1f28da9ca60a00c420a47e722dc95396e8f2e78e89293544a551d3cf73f99232cfdb8fed7eb31bd567c440273e0d2a33b4b019e4e49c260abb182987bdd7fbab1bf68da549ad168acbf79c22ff03bae9324b2299e0d13aa5283080ea3036b96de0e51c4612d3dded578e0a",
			isChained:     true,
			returnsError:  false,
		},
		{
			testName:      "both input UPPs are signed (not chained)",
			prevUPP:       "9522c41056bd9b856c6e4a24bf71f2ac2de1018300c4207c2871a46846f4b32e56c219d969e1d54576fd43830b30485670cd7e0208fff9c44068a0502ec315127c018bc3b75f7af084a6f751a7f6cd1a849da977518b1b31319169c282c5830d933ca8b082c8b2b79ef384fd8356d57c486aa57c79b647830f",
			subsequentUPP: "9522c41056bd9b856c6e4a24bf71f2ac2de1018300c42068cf72a074155754ce0ef903a330fea4516a80ef0116a84cedc7bfb0dc8c6af0c4400c8965b4ee5b52b6e95b19a0bae3c156b460ed8b2f77025bf48019848f5a9070145c88f2586c25e09f247a26bebebbdb9d931f887e5579f2f052ddbf41634e07",
			isChained:     false,
			returnsError:  true,
		},
		{
			testName:      "UPPs with empty signatures",
			prevUPP:       "9623c410ba70ad8ba5644e589a3b224ac0f0153fc40000c4207a1223d6b5dc387b5a7682be5ad8d478cfd00506b4de2584aaf937ad09df2b44c400",
			subsequentUPP: "9623c410ba70ad8ba5644e589a3b224ac0f0153fc40000c42055f640b3b97b7fce1422a56b7fa5cfe21092d8837cf300e0428ad050fbde6a52c400",
			isChained:     false,
			returnsError:  true,
		},
		{
			testName:      "first UPP with empty signature",
			prevUPP:       "9522c41056bd9b856c6e4a24bf71f2ac2de1018300c420de3858d827ffd41ff7dcc2b0729951766886081d97f925c75b3ad0fa6c7b14e2c400",
			subsequentUPP: "9623c41056bd9b856c6e4a24bf71f2ac2de10183c4405819a9df6b4dc176a753a30ccd4b606b37265042876267138426525c12e7a06f92eb2b30dbc1142e7dd73d1376f390671be2790e1e432fce68fc1f28da9ca60a00c420a47e722dc95396e8f2e78e89293544a551d3cf73f99232cfdb8fed7eb31bd567c440273e0d2a33b4b019e4e49c260abb182987bdd7fbab1bf68da549ad168acbf79c22ff03bae9324b2299e0d13aa5283080ea3036b96de0e51c4612d3dded578e0a",
			isChained:     false,
			returnsError:  true,
		},
		{
			testName:      "second UPP with empty previous signature",
			prevUPP:       "9522c41056bd9b856c6e4a24bf71f2ac2de1018300c420de3858d827ffd41ff7dcc2b0729951766886081d97f925c75b3ad0fa6c7b14e2c4405819a9df6b4dc176a753a30ccd4b606b37265042876267138426525c12e7a06f92eb2b30dbc1142e7dd73d1376f390671be2790e1e432fce68fc1f28da9ca60a",
			subsequentUPP: "9623c41056bd9b856c6e4a24bf71f2ac2de10183c40000c420a47e722dc95396e8f2e78e89293544a551d3cf73f99232cfdb8fed7eb31bd567c440273e0d2a33b4b019e4e49c260abb182987bdd7fbab1bf68da549ad168acbf79c22ff03bae9324b2299e0d13aa5283080ea3036b96de0e51c4612d3dded578e0a",
			isChained:     false,
			returnsError:  true,
		},
		{
			testName:      "input not chained",
			prevUPP:       "9623c410ba70ad8ba5644e589a3b224ac0f0153fc440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee1900c4207a1223d6b5dc387b5a7682be5ad8d478cfd00506b4de2584aaf937ad09df2b44c440ebbc5ab7d1c40fb513bb751fcf954f3f1c9055acf9d456eeba63cd0f86c9f2cf6f52d1618870baad90c5c5b8c30dd5e9969b0cf4d2ab41c1a4fed11ef7803517",
			subsequentUPP: "9623c410ba70ad8ba5644e589a3b224ac0f0153fc4404a9d2c0090b362595d8289a118363d31e9db66e18a153056fdd959a76d0ef7c8dedfbcc7cd83d482bc5bd1fd4f6d4fcc083d20f74f5ee497f16c08ea9b6799f200c42055f640b3b97b7fce1422a56b7fa5cfe21092d8837cf300e0428ad050fbde6a52c440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee19",
			isChained:     false,
			returnsError:  false,
		},
		{
			testName:      "signature of first upp one byte too short",
			prevUPP:       "9623c410ba70ad8ba5644e589a3b224ac0f0153fc4404a9d2c0090b362595d8289a118363d31e9db66e18a153056fdd959a76d0ef7c8dedfbcc7cd83d482bc5bd1fd4f6d4fcc083d20f74f5ee497f16c08ea9b6799f200c42055f640b3b97b7fce1422a56b7fa5cfe21092d8837cf300e0428ad050fbde6a52c43fd6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee",
			subsequentUPP: "9623c410ba70ad8ba5644e589a3b224ac0f0153fc440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee1900c4207a1223d6b5dc387b5a7682be5ad8d478cfd00506b4de2584aaf937ad09df2b44c440ebbc5ab7d1c40fb513bb751fcf954f3f1c9055acf9d456eeba63cd0f86c9f2cf6f52d1618870baad90c5c5b8c30dd5e9969b0cf4d2ab41c1a4fed11ef7803517",
			isChained:     false,
			returnsError:  false,
		},
		{
			testName:      "prev signature of second upp one byte too short",
			prevUPP:       "9623c410ba70ad8ba5644e589a3b224ac0f0153fc4404a9d2c0090b362595d8289a118363d31e9db66e18a153056fdd959a76d0ef7c8dedfbcc7cd83d482bc5bd1fd4f6d4fcc083d20f74f5ee497f16c08ea9b6799f200c42055f640b3b97b7fce1422a56b7fa5cfe21092d8837cf300e0428ad050fbde6a52c440d6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee19",
			subsequentUPP: "9623c410ba70ad8ba5644e589a3b224ac0f0153fc43fd6421175b745e77d87abbeb3ca2cfd956e677f73ab7a7984ce8633c98ba1a9a680d53af48d5c1dc795661792b59e6795a5542be87c1fc46be4d0816b3bfcee00c4207a1223d6b5dc387b5a7682be5ad8d478cfd00506b4de2584aaf937ad09df2b44c440ebbc5ab7d1c40fb513bb751fcf954f3f1c9055acf9d456eeba63cd0f86c9f2cf6f52d1618870baad90c5c5b8c30dd5e9969b0cf4d2ab41c1a4fed11ef7803517",
			isChained:     false,
			returnsError:  false,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			// parse test parameters into correct types
			var err error

			prevBytes, err := hex.DecodeString(currTest.prevUPP)
			requirer.NoErrorf(err, "Decoding test prevUPP from string failed: %v, string was: %v", err, currTest.prevUPP)

			prevUPP, err := Decode(prevBytes)
			requirer.NoErrorf(err, "Decoding test prevUPP from bytes failed: %v, string was: %v", err, currTest.prevUPP)

			subsequentBytes, err := hex.DecodeString(currTest.subsequentUPP)
			requirer.NoErrorf(err, "Decoding test subsequentUPP from string failed: %v, string was: %v", err, currTest.subsequentUPP)

			subsequentUPP, err := Decode(subsequentBytes)
			requirer.NoErrorf(err, "Decoding test subsequentUPP from bytes failed: %v, string was: %v", err, currTest.subsequentUPP)

			// decode test input
			chainOK, err := CheckChainLink(prevUPP, subsequentUPP)
			if currTest.isChained {
				asserter.Truef(chainOK, "chain check failed with valid input")
			} else {
				asserter.Falsef(chainOK, "chain check succeeded with invalid input")
			}
			if currTest.returnsError {
				asserter.Errorf(err, "chain check did not return error as expected")
			} else {
				asserter.NoErrorf(err, "chain check returned unexpected error: %v", err)
			}
		})
	}
}
