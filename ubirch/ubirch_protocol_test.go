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
 */

package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/stretchr/testify/assert"
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

//TestCreateSignedMessage tests 'Signed' type UPP creation from given user data. Data is hashed, hash is
//used as UPP payload and then the created encoded UPP data (without the signature, as its
//non-deterministic) is compared to the expected values
func TestCreateSignedMessage(t *testing.T) {
	var tests = []struct {
		testName               string
		privateKey             string
		deviceUUID             string
		dataToHash             string
		expectedUPPNoSignature string
	}{
		{
			testName:               "Data='1'",
			privateKey:             "6f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937",
			deviceUUID:             "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			dataToHash:             "31", //equals the character "1" string
			expectedUPPNoSignature: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440",
		},
		{
			testName:               "Data='Hello World!'",
			privateKey:             "6f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937",
			deviceUUID:             "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			dataToHash:             "48656c6c6f20576f726c6421", //"Hello World!"
			expectedUPPNoSignature: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			//Create new crypto context
			context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			protocol := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
			//Load reference data into context
			setProtocolOk := asserter.NoError(setProtocolContext(protocol, defaultName, currTest.deviceUUID, currTest.privateKey, defaultLastSig))
			if !setProtocolOk {
				return
			}
			//Create hash of input data
			dataToHashBytes, err := hex.DecodeString(currTest.dataToHash)
			decodeDataToHashOk := asserter.NoErrorf(err, "Test configuration string can't be decoded.\nString was: %v", currTest.dataToHash)
			if !decodeDataToHashOk {
				return
			}
			hash := sha256.Sum256(dataToHashBytes)
			//Create 'Signed' type UPP packet
			upp, err := protocol.Sign(defaultName, hash[:], Signed)
			if err != nil {
				t.Errorf("signing failed: %v", err)
			}
			//Check created UPP (without signature at the end, as it's non-deterministic)
			expectedUPPBytesNoSignature, err := hex.DecodeString(currTest.expectedUPPNoSignature)
			if err != nil {
				t.Fatalf("Error decoding UPP data string: %v, string was: %v", err, currTest.expectedUPPNoSignature)
			}
			UPPBytesNoSignature := upp[:len(upp)-64]
			if !(bytes.Equal(expectedUPPBytesNoSignature, UPPBytesNoSignature)) {
				t.Errorf("UPP data comparison (without signature) failed:\nexpected: %x\ngot:      %x", expectedUPPBytesNoSignature, UPPBytesNoSignature)
			}
		})
	}
}

//TestCreateChainedMessage tests 'Chained' type UPP creation across multiple chained packets. Each input is hashed, hash is
//used as UPP payload and then the created encoded UPP data (without the signature, as its
//non-deterministic) is compared to the expected values. During this, the signature of the last UPP is manually copied into the
//expected data, as ECDSA is non-deterministic, thus only testing if the basic UPP encoding works.
func TestCreateChainedMessage(t *testing.T) {
	var tests = []struct {
		testName                   string
		privateKey                 string
		deviceUUID                 string
		lastSignature              string
		dataInputs                 []string
		expectedChainedNoSignature []string
	}{
		{
			"Test1",
			"8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937",
			"6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			[]string{
				"01",
				"02",
				"03",
			},
			[]string{
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac440",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c440",
			},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			//Create new crypto context
			context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			protocol := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
			//Load reference data into context
			setProtocolContext(protocol, defaultName, currTest.deviceUUID, currTest.privateKey, currTest.lastSignature)
			//Set 'last signature' variable according to test parameters
			lastSignatureBytes, err := hex.DecodeString(currTest.lastSignature)
			if err != nil {
				t.Fatalf("Error decoding input data string: %v, string was: %v", err, currTest.lastSignature)
			}
			if len(lastSignatureBytes) != 64 {
				t.Fatalf("Error: wrong size for last signature, expected 64 bytes but got: %v bytes", len(lastSignatureBytes))
			}
			//Loop over input data and expected UPP packets
			for i := 0; i < len(currTest.dataInputs); i++ {
				//Load expected UPP data
				expectedUPPBytesNoSignature, err := hex.DecodeString(currTest.expectedChainedNoSignature[i])
				if err != nil {
					t.Fatalf("Error decoding expected data string: %v, string was: %v", err, currTest.expectedChainedNoSignature[i])
				}
				//Overwrite 'last signature' field in expected UPP data with signature of last packet
				copy(expectedUPPBytesNoSignature[22:22+64], lastSignatureBytes)

				//Create hash of input data for the payload
				dataInputBytes, err := hex.DecodeString(currTest.dataInputs[i])
				if err != nil {
					t.Fatalf("Error decoding input data string: %v, string was: %v", err, currTest.dataInputs[i])
				}
				hash := sha256.Sum256(dataInputBytes)
				//Create UPP packet with hash as payload
				upp, err := protocol.Sign(defaultName, hash[:], Chained)
				if err != nil {
					t.Errorf("signing failed: %v", err)
				}
				//Save signature from newly created UPP for next round
				lastSignatureBytes = upp[len(upp)-64:]

				//Check if created UPP data is same as expected, not comparing the signature
				UPPBytesNoSignature := upp[:len(upp)-64]
				if !bytes.Equal(expectedUPPBytesNoSignature, UPPBytesNoSignature) {
					t.Errorf("UPP data comparison (without signature) failed:\nexpected: %x\ngot:      %x", expectedUPPBytesNoSignature, UPPBytesNoSignature)
				}
			}
		})
	}
}

//TestVerifyHashedMessage in its current state only tests if the ECDSA library behaves as expected
func TestVerifyHashedMessage(t *testing.T) {
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

func TestProtocol_Verify(t *testing.T) {
	var tests = []struct {
		testName       string
		UUID           string
		pubKey         string
		inputUPP       string
		expectedResult bool
	}{
		{
			testName:       "",
			UUID:           "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			pubKey:         "",
			inputUPP:       "",
			expectedResult: true,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			// Create new crypto context
			context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			protocol := &Protocol{Crypto: context, Signatures: nil}
			// Load reference data into context
			id, err := uuid.Parse(currTest.UUID)
			if err != nil {
				t.Fatalf("Error parsing UUID from string: %v, string was: %v", err, currTest.pubKey)
			}
			// Set public key for verification
			pubKeyBytes, err := hex.DecodeString(currTest.pubKey)
			if err != nil {
				t.Fatalf("Error decoding public key from string: %v, string was: %v", err, currTest.pubKey)
			}
			err = protocol.Crypto.SetPublicKey(defaultName, id, pubKeyBytes)
			if err != nil {
				t.Fatalf("Error setting public key bytes in crypto context: : %v,", err)
			}

		})
	}
}
