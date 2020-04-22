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
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

//BenchmarkSign benchmarks only UPP creation via Protocol.Sign() (NOT Crypto.Sign()) with various payload sizes
func BenchmarkSign(b *testing.B) {
	//Define data for all benchmarks to run
	benchmarks := []struct {
		testDescription  string
		deviceName       string
		deviceUUID       string
		devicePrivateKey string
		deviceLastSig    string
		inputSizeBytes   int
		signProtocol     ProtocolType
	}{
		{"Plain-32Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 32, Plain},
		{"Plain-64Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 64, Plain},
		{"Plain-1kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Plain},
		{"Plain-100kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Plain},
		{"Plain-1MB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Plain},

		{"Signed-32Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 32, Signed},
		{"Signed-64Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 64, Signed},
		{"Signed-1kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Signed},
		{"Signed-100kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Signed},
		{"Signed-1MB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Signed},

		{"Chained-32Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 32, Chained},
		{"Chained-64Bytes", defaultName, defaultUUID, defaultPriv, defaultLastSig, 64, Chained},
		{"Chained-1kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Chained},
		{"Chained-100kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Chained},
		{"Chained-1MB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Chained},
	}

	//Iterate over all benchmarks
	for _, bm := range benchmarks {
		//Create new crypto context
		context := &CryptoContext{
			Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			Names:    map[string]uuid.UUID{},
		}
		p := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
		//Load reference data into context
		setProtocolContext(p, bm.deviceName, bm.deviceUUID, bm.devicePrivateKey, "", bm.deviceLastSig)
		//Generate pseudrandom input data
		inputData := deterministicPseudoRandomBytes(0, bm.inputSizeBytes)
		//Run the current benchmark
		b.Run(bm.testDescription, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoded, err := p.Sign(bm.deviceName, inputData, bm.signProtocol)
				if err != nil {
					b.Fatalf("Protocol.Sign() failed with error %v", err)
				}
				_ = encoded
			}
		})
	}
}

//BenchmarkHashUserDataAndSign benchmarks UPP creation with user data input:
//SHA256 hash of user data is calculated and then used as payload in the UPP creation via Protocol.Sign() (NOT Crypto.Sign())
func BenchmarkHashUserDataAndSign(b *testing.B) {
	//Define data for all benchmarks to run
	benchmarks := []struct {
		testDescription   string
		deviceName        string
		deviceUUID        string
		devicePrivateKey  string
		deviceLastSig     string
		userDataSizeBytes int
		signProtocol      ProtocolType
	}{
		{"Signed-defaultDataSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, defaultDataSize, Signed},
		{"Signed-1kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Signed},
		{"Signed-100kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Signed},
		{"Signed-1MB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Signed},

		{"Chained-defaultDataSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, defaultDataSize, Chained},
		{"Chained-1kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Chained},
		{"Chained-100kB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Chained},
		{"Chained-1MB", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Chained},
	}

	//Iterate over all benchmarks
	for _, bm := range benchmarks {
		//Create new crypto context
		context := &CryptoContext{
			Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			Names:    map[string]uuid.UUID{},
		}
		p := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
		//Load reference data into context
		setProtocolContext(p, bm.deviceName, bm.deviceUUID, bm.devicePrivateKey, "", bm.deviceLastSig)
		//Generate pseudrandom input data
		inputData := deterministicPseudoRandomBytes(0, bm.userDataSizeBytes)
		//Run the current benchmark
		b.Run(bm.testDescription, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hash := sha256.Sum256(inputData)
				encoded, err := p.Sign(bm.deviceName, hash[:], bm.signProtocol)
				if err != nil {
					b.Fatalf("Protocol.Sign() failed with error %v", err)
				}
				_ = encoded
			}
		})
	}
}
