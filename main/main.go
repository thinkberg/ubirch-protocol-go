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
	"fmt"
	"github.com/miekg/pkcs11"
	"math/rand"
	"strconv"
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
	p := pkcs11.New("libcs_pkcs11_R3.so") //make sure to have 'export LD_LIBRARY_PATH=~/.utimaco/' or use absolute path to .so
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()
	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}

	defer p.CloseSession(session)
	err = p.Login(session, pkcs11.CKU_USER, "TestSlotPin")
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)
	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := p.Digest(session, []byte("Hello World"))
	if err != nil {
		panic(err)
	}
	fmt.Println("SHA1 Hash of \"Hello World\":")
	for _, d := range hash {
		fmt.Printf("%02x", d)
	}
	fmt.Println()
	fmt.Println("Verify with: echo -n \"Hello World\" | sha1sum -")
	fmt.Println()
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	keyId := src.Int()
	tokenLabel := strconv.FormatInt(int64(keyId), 16) + "_Key"
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	_, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		fmt.Println("Failed to generate keypair!")
	} else {
		fmt.Println("Created key with label: " + tokenLabel)
		fmt.Printf("Got private key handle %v\n", pvk)
	}
}
