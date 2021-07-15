/*
 * Copyright (c) 2021 ubirch GmbH.
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
 */
package ubirch

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/google/uuid"
)

//BenchmarkCryptoContextSign benchmarks hashing and signing directly with the crypto interface (with go or pkcs#11
// ecdsa lib depending on test flags).
func BenchmarkCryptoContextSign(b *testing.B) {
	//Define data for all benchmarks to run
	benchmarks := []struct {
		testDescription  string
		deviceUUID       string
		devicePrivateKey string
		inputSizeBytes   int
	}{
		{"32BytesData", defaultUUID, defaultPriv, 32},
		{"64BytesData", defaultUUID, defaultPriv, 64},
		{"1024BytesData", defaultUUID, defaultPriv, 1024},
		{"1MBytesData", defaultUUID, defaultPriv, 1024 * 1024},
	}

	//Iterate over all benchmarks
	for _, bm := range benchmarks {
		requirer := require.New(b)

		//create golang or pkcs#11 crypto crypto depending on test settings
		crypto, err := getCryptoContext()
		requirer.NoError(err, "creating crypto context failed")

		id := uuid.MustParse(bm.deviceUUID)
		privBytes, err := hex.DecodeString(bm.devicePrivateKey)

		//Set the PrivateKey and check, that it is set correctly
		requirer.NoErrorf(crypto.SetKey(id, privBytes), "Setting the Private Key failed")

		//Generate pseudorandom input data
		inputData := deterministicPseudoRandomBytes(0, bm.inputSizeBytes)

		//Run the current benchmark
		b.Run(bm.testDescription, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				signature, err := crypto.Sign(id, inputData)
				if err != nil {
					b.Fatalf("Protocol.Sign() failed with error %v", err)
				}
				_ = signature
			}
		})
		if *pkcs11CryptoTests { // remove keys again for pkcs#11 tests
			requirer.NoError(pkcs11DeleteKeypair(crypto, id))
		}

		requirer.NoError(crypto.Close(), "error when closing crypto context")
	}
}

//BenchmarkCryptoContextSignHash benchmarks signing only directly with the crypto interface (with go or pkcs#11
// ecdsa lib depending on test flags).
func BenchmarkCryptoContextSignHash(b *testing.B) {

	requirer := require.New(b)

	//create golang or pkcs#11 crypto crypto depending on test settings
	crypto, err := getCryptoContext()
	requirer.NoError(err, "creating crypto context failed")

	id := uuid.MustParse(defaultUUID)
	privBytes, err := hex.DecodeString(defaultPriv)

	//Set the PrivateKey and check, that it is set correctly
	requirer.NoErrorf(crypto.SetKey(id, privBytes), "Setting the Private Key failed")

	//Generate pseudorandom input data
	hashData := deterministicPseudoRandomBytes(0, crypto.HashLength())

	//Run the current benchmark
	b.Run("SignHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signature, err := crypto.SignHash(id, hashData)
			if err != nil {
				b.Fatalf("Protocol.SignHash() failed with error %v", err)
			}
			_ = signature
		}
	})
	if *pkcs11CryptoTests { // remove keys again for pkcs#11 tests
		requirer.NoError(pkcs11DeleteKeypair(crypto, id))
	}

	requirer.NoError(crypto.Close(), "error when closing crypto context")

}
