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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/thinkberg/ubirch-protocol-go/ubirch"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func saveProtocolContext(v interface{}) error {
	contextBytes, _ := json.Marshal(v)
	err := ioutil.WriteFile("protocol.json", contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

func loadProtocolContext(v interface{}) error {
	contextBytes, err := ioutil.ReadFile("protocol.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, &v)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		return nil
	}
}

func main() {
	name := "A"

	context := &ubirch.CryptoContext{
		Keystore:      &keystore.Keystore{},
		LastSignature: nil,
	}
	p := ubirch.Protocol{
		Crypto: context,
	}

	err := loadProtocolContext(p)
	if err != nil {
		log.Printf("keystore not found, or unable to loadProtocolContext: %v", err)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("unable to create signing key: %v", err)
		}
		uid, _ := uuid.NewRandom()
		err = context.AddKey(name, uid, priv)
		if err != nil {
			log.Fatalf("can't add key to key store: %v", err)
		}
	}

	data, _ := hex.DecodeString("010203040506070809FF")
	encoded, err := p.Sign("A", data, 0x22)
	if err != nil {
		log.Fatal("creating signed upp failed: %v", err)
	}
	log.Print(hex.EncodeToString(encoded))

	go func() {
		log.Println("Listening signals...")
		c := make(chan os.Signal, 1) // we need to reserve to buffer size 1, so the notifier are not blocked
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	}()

	_ = saveProtocolContext(p)
}
