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
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"math/big"
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
	p := pkcs11.New("libcs_pkcs11_R3.so") //make sure to have 'export LD_LIBRARY_PATH=~/.utimaco/' or use absolute path to .so
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}

	err = p.Login(session, pkcs11.CKU_USER, "TestSlotPin")
	if err != nil {
		panic(err)
	}

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
	//privKey := &ubirch.PKCS11ECDSAPrivKey{
	//	PubKey:        pubKey,
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

	//close testing pkcs#11 interface
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
	p.Destroy()

	//test pkcs crypto interface
	mydata := []byte("12345678901234564890123456789012")
	myuuid := uuid.MustParse("e94069b0-36ad-4bb5-8397-803e30461d4c")
	myCrypto, err := ubirch.NewECDSAPKCS11CryptoContext(pkcs11.New("libcs_pkcs11_R3.so"), "TestSlotPin", 0)
	if err != nil {
		panic(err)
	}

	if !myCrypto.PrivateKeyExists(myuuid) {
		myCrypto.GenerateKey(myuuid)
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

	fmt.Printf("Data to sign: 0x%x\n", mydata)
	signature, err := myCrypto.SignHash(myuuid, mydata)
	if err != nil {
		fmt.Printf("Error signing hash: %s\n", err)
	} else {
		fmt.Printf("Signature: %x\n", signature)
	}

	err = myCrypto.Close()
	if err != nil {
		panic(err)
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
	if ecdsa.Verify(pubKey, mydata, r, s) {
		fmt.Println("Signature OK")
	} else {
		fmt.Println("Signature not OK")
	}

}
