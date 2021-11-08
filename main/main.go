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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func saveProtocolContext(p *ubirch.Protocol) error {
	contextBytes, _ := json.Marshal(p)
	err := ioutil.WriteFile("protocol.json", contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

func loadProtocolContext(p *ubirch.Protocol) error {
	contextBytes, err := ioutil.ReadFile("protocol.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		return nil
	}
}

func main() {
	uid := uuid.MustParse("10adfe73-9819-4121-b575-97e614ab441a")

	p := ubirch.Protocol{
		Crypto: &ubirch.ECDSACryptoContext{
			Keystore: ubirch.NewEncryptedKeystore([]byte("2234567890123456")), //this is only a demo code secret, use a real secret here in your code
		},
	}

	err := loadProtocolContext(&p)
	if err != nil {
		log.Printf("keystore not found, or unable to load: %v", err)
		err = p.GenerateKey(uid)
		if err != nil {
			log.Fatalf("can't add key to key store: %v", err)
		}
	}

	data, _ := hex.DecodeString("010203040506070809FF")
	hash := sha256.Sum256(data)
	encoded, err := p.Sign(
		&ubirch.SignedUPP{
			Version:   ubirch.Signed,
			Uuid:      uid,
			Hint:      0,
			Payload:   hash[:],
			Signature: nil,
		})
	if err != nil {
		log.Fatalf("creating signed upp failed: %v", err)
	}
	log.Print(hex.EncodeToString(encoded))

	go func() {
		log.Println("Listening signals...")
		c := make(chan os.Signal, 1) // we need to reserve to buffer size 1, so the notifier are not blocked
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	}()

	_ = saveProtocolContext(&p)
}
