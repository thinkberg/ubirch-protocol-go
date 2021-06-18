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
	"github.com/miekg/pkcs11"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"io/ioutil"
	"math/big"
	"time"
)

//func saveProtocolContext(p *ubirch.Protocol) error {
//	contextBytes, _ := json.Marshal(p)
//	err := ioutil.WriteFile("protocol.json", contextBytes, 444)
//	if err != nil {
//		log.Printf("unable to store protocol context: %v", err)
//		return err
//	} else {
//		log.Printf("saved protocol context")
//		return nil
//	}
//}

//func loadProtocolContext(p *ubirch.Protocol) error {
//	contextBytes, err := ioutil.ReadFile("protocol.json")
//	if err != nil {
//		return err
//	}
//
//	err = json.Unmarshal(contextBytes, p)
//	if err != nil {
//		log.Fatalf("unable to deserialize context: %v", err)
//		return err
//	} else {
//		log.Printf("loaded protocol context")
//		return nil
//	}
//}

//func main() {
//
//	p := ubirch.Protocol{
//		Crypto: &ubirch.ECDSACryptoContext{
//			Keystore: ubirch.NewEncryptedKeystore([]byte("2234567890123456")), //this is only a demo code secret, use a real secret here in your code
//		},
//	}
//
//	//err := loadProtocolContext(&p)
//	//if err != nil {
//	//	log.Printf("keystore not found, or unable to load: %v", err)
//	//	uid, _ := uuid.NewRandom()
//	//	err = p.GenerateKey(uid)
//	//	if err != nil {
//	//		log.Fatalf("can't add key to key store: %v", err)
//	//	}
//	//}
//
//	uid := uuid.New()
//	err := p.GenerateKey(uid)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	data, _ := hex.DecodeString("010203040506070809FF")
//	hash := sha256.Sum256(data)
//	encoded, err := p.Sign(
//		&ubirch.SignedUPP{
//			Version:   ubirch.Signed,
//			Uuid:      uid,
//			Hint:      0,
//			Payload:   hash[:],
//			Signature: nil,
//		})
//	if err != nil {
//		log.Fatalf("creating signed upp failed: %v", err)
//	}
//	log.Printf("upp: %s", hex.EncodeToString(encoded))
//
//	go func() {
//		log.Println("Listening signals...")
//		c := make(chan os.Signal, 1) // we need to reserve to buffer size 1, so the notifier are not blocked
//		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
//	}()

//_ = saveProtocolContext(&p)
//}

func main() {
	//p := pkcs11.New("libcs_pkcs11_R3.so") //make sure to have 'export LD_LIBRARY_PATH=~/.utimaco/' or use absolute path to .so
	//err := p.Initialize()
	//if err != nil {
	//	panic(err)
	//}
	//
	//slots, err := p.GetSlotList(true)
	//if err != nil {
	//	panic(err)
	//}
	//session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	//if err != nil {
	//	panic(err)
	//}
	//
	//err = p.Login(session, pkcs11.CKU_USER, "TestSlotPin")
	//if err != nil {
	//	panic(err)
	//}

	////sign something
	//mydata := []byte("Hello World")
	//p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, privkeyh)
	//signature, err := p.Sign(session, mydata)
	//if err != nil {
	//	fmt.Println("Signing failed:")
	//	panic(err)
	//}
	//
	//fmt.Println("ECDSA signature of " + string(mydata) + " :")
	//for _, d := range signature {
	//	fmt.Printf("%02x", d)
	//}
	//fmt.Println("")

	////Create a CSR using the HSM key
	//subjectCountry := "DE"
	//subjectOrganization := "Test GmbH"
	//
	//CertTemplate := &x509.CertificateRequest{
	//	SignatureAlgorithm: x509.ECDSAWithSHA256,
	//	Subject: pkix.Name{
	//		Country:      []string{subjectCountry},
	//		Organization: []string{subjectOrganization},
	//		CommonName:   "SomeSortOfID",
	//	},
	//}

	////create a pkcs11 private key struct for signing
	//privKey := &ubirch.ECDSAPKCS11PrivKey{
	//	pubKey:        pubKey,
	//	PKCS11Ctx:     p,
	//	PrivKeyHandle: privkeyh,
	//	SessionHandle: session,
	//}
	//
	//myCSR, err := x509.CreateCertificateRequest(nil, CertTemplate, privKey)
	//
	//if err != nil {
	//	fmt.Println("Creating CSR failed:")
	//	panic(err)
	//}
	//fmt.Println("Generated CSR:")
	//fmt.Println(string(myCSR))
	//for _, d := range myCSR {
	//	fmt.Printf("%02x", d)
	//}
	//
	////dump csr in file for checking
	//err = ioutil.WriteFile("./mycsr.der", myCSR, 0644)
	//if err != nil {
	//	fmt.Println("Saving CSR failed:")
	//	panic(err)
	//}

	////close testing pkcs#11 interface
	//p.Logout(session)
	//p.CloseSession(session)
	//p.Finalize()
	//p.Destroy()

	//test pkcs crypto interface
	mydata := []byte("12345678901234564890123456789012HelloWorld!")
	myuuid := uuid.MustParse("e94069b0-36ad-4bb5-8397-803e30461d4c")
	myPkcs11Context := pkcs11.New("libcs_pkcs11_R3.so")
	myCrypto, err := ubirch.NewECDSAPKCS11CryptoContext(myPkcs11Context, "TestSlotPin", 0, 2, 50*time.Millisecond)
	if err != nil {
		panic(err)
	}
	defer func(myCrypto *ubirch.ECDSAPKCS11CryptoContext) {
		err := myCrypto.Close()
		if err != nil {
			fmt.Printf("Error when closing crypto context: %s\n", err)
		}
	}(myCrypto)

	privExists, err := myCrypto.PrivateKeyExists(myuuid)
	if err != nil {
		panic(err)
	}
	if !privExists {
		err = myCrypto.GenerateKey(myuuid)
		if err != nil {
			panic(err)
		}
		fmt.Println("Generated a new keypair")
	} else {
		fmt.Println("Found existing key")
	}
	pubKeyBytes, err := myCrypto.GetPublicKey(myuuid)
	if err != nil {
		fmt.Printf("Pubkey error: %s\n", err)
	} else {
		fmt.Printf("Pubkey bytes: %x\n", pubKeyBytes)
	}

	fmt.Printf("Data to sign: %s\n", mydata)
	signature, err := myCrypto.Sign(myuuid, mydata)
	if err != nil {
		panic(fmt.Sprintf("error signing hash: %s\n", err))
	} else {
		fmt.Printf("Signature: %x\n", signature)
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
	hash := sha256.Sum256(mydata)
	if ecdsa.Verify(pubKey, hash[:], r, s) {
		fmt.Println("Signature OK")
	} else {
		fmt.Println("Signature not OK")
	}

	fmt.Println("Verifying with lib")
	sigOK, err := myCrypto.Verify(myuuid, mydata, signature)
	if err != nil {
		panic(fmt.Sprintf("Verify (lib) failed: %s", err))
	}
	if sigOK {
		fmt.Println("Signature OK")
	} else {
		fmt.Println("Signature not OK")
	}

	//create a CSR
	myCSR, err := myCrypto.GetCSR(myuuid, "DE", "Test GmbH")
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
