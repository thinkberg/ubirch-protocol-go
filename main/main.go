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

func main() {
	uid, _ := uuid.NewRandom()

	context := &ubirch.CryptoContext{
		Keystore:      &keystore.Keystore{},
		LastSignature: nil,
	}
	p := ubirch.Protocol{
		Crypto: context,
		Uuid:   uid,
	}

	ksbytes, err := ioutil.ReadFile("ubirch.ks")
	if err != nil {
		log.Printf("keystore not found, or unable to load: %v", err)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("unable to create signing key: %v", err)
		}
		err = context.AddKey(p.Uuid, priv)
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

	ksbytes, _ = json.Marshal(context.Keystore)
	err = ioutil.WriteFile("ubirch.ks", ksbytes, 444)
	if err != nil {
		log.Printf("unable to store keystore: %v", err)
	}
}
