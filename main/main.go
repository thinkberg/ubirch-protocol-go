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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"io/ioutil"
	"math/big"
	"sync"
	"time"
)

func signAndCheck(myCrypto *ubirch.ECDSAPKCS11CryptoContext, myUuid uuid.UUID, myData []byte, wg *sync.WaitGroup) error {

	defer wg.Done()

	fmt.Printf("Data to sign: %s\n", myData)
	signature, err := myCrypto.Sign(myUuid, myData)
	if err != nil {
		panic(fmt.Sprintf("error signing hash: %s\n", err))
	} else {
		fmt.Printf("Signature: %x\n", signature)
	}

	pubKeyBytes, err := myCrypto.GetPublicKey(myUuid)
	if err != nil {
		return fmt.Errorf("Pubkey error: %s\n", err)
	} else {
		fmt.Printf("Pubkey bytes: %x\n", pubKeyBytes)
	}

	//check the signature locally
	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:32])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[32:(32 + 32)])

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	fmt.Println("Verifying locally")
	hash := sha256.Sum256(myData)
	if ecdsa.Verify(pubKey, hash[:], r, s) {
		fmt.Println("Signature OK")
	} else {
		return fmt.Errorf("signature not OK")
	}

	fmt.Println("Verifying with lib")
	sigOK, err := myCrypto.Verify(myUuid, myData, signature)
	if err != nil {
		return fmt.Errorf("verify (lib) failed: %s", err)
	}
	if sigOK {
		fmt.Println("Signature OK")
	} else {
		return fmt.Errorf("signature not OK")
	}
	return nil
}

func main() {
	//test pkcs crypto interface
	myUuid := uuid.MustParse("e94069b0-36ad-4bb5-8397-803e30461d4c")
	myCrypto, err := ubirch.NewECDSAPKCS11CryptoContext(
		"libcs_pkcs11_R3.so",
		"TestSlotPin",
		0,
		false,
		2,
		50*time.Millisecond)
	if err != nil {
		panic(err)
	}
	defer func(myCrypto *ubirch.ECDSAPKCS11CryptoContext) {
		err := myCrypto.Close()
		if err != nil {
			fmt.Printf("Error when closing crypto context: %s\n", err)
		}
	}(myCrypto)

	privExists, err := myCrypto.PrivateKeyExists(myUuid)
	if err != nil {
		panic(err)
	}
	if !privExists {
		err = myCrypto.GenerateKey(myUuid)
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated a new keypair")
	} else {
		fmt.Println("Found existing key")
	}

	//test signing and check signature with threads
	var wg sync.WaitGroup
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go signAndCheck(myCrypto, myUuid, []byte("12345678901234564890123456789012HelloWorld!"), &wg)
	}
	wg.Wait()

	//create a CSR
	myCSR, err := myCrypto.GetCSR(myUuid, "DE", "Test GmbH")
	if err != nil {
		panic(fmt.Sprintf("creating CSR failed: %s", err))
	}
	//dump csr in file for checking
	err = ioutil.WriteFile("./mycsr.der", myCSR, 0644)
	if err != nil {
		fmt.Println("Saving CSR failed:")
		panic(err)
	} else {
		fmt.Println("Created and saved CSR")
	}

	my2ndUuid := uuid.New()
	err = myCrypto.SetKey(my2ndUuid, []byte("12345678901234567890123456789012"))
	if err != nil {
		panic(err)
	}
	csr2, err := myCrypto.GetCSR(my2ndUuid, "DE", "Test5000")
	if err != nil {
		panic(err)
	}

	//dump csr in file for checking
	err = ioutil.WriteFile("./mycsr2.der", csr2, 0644)
	if err != nil {
		fmt.Println("Saving CSR2 failed:")
		panic(err)
	} else {
		fmt.Println("Created and saved CSR2")
	}

}
