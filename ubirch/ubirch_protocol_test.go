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
	"log"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

// test fixtures
const (
	testName = "A"
	testUUID = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"
	testPriv = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"
	testPub  = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771"

	// expected messages
	expectedSigned = "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440"
)

// expected sequence of chained messages (contained signatures are placeholders only, ecdsa is not deterministic)
var expectedChained = [...]string{
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac440",
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440",
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c440",
}

var context = &CryptoContext{
	Keystore: &keystore.Keystore{},
	Names:    map[string]uuid.UUID{},
}

var protocol = Protocol{
	Crypto:     context,
	Signatures: map[uuid.UUID][]byte{},
}

func (c *CryptoContext) GetLastSignature() ([]byte, error) {
	return nil, nil
}

func bytesToPrivateKey(bytes []byte) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.D = new(big.Int)
	priv.D.SetBytes(bytes)
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())
	return priv
}

func init() {
	id := uuid.MustParse(testUUID)
	privBytes, err := hex.DecodeString(testPriv)
	if err != nil {
		panic(err)
	}
	err = context.storePrivateKey(testName, id, bytesToPrivateKey(privBytes))
	if err != nil {
		panic(err)
	}
}

func TestDecodeArrayToStruct(t *testing.T) {
	upp, _ := hex.DecodeString("9623c4104f6b64a7a5c9483786c00d32bc8e03c0c440936a6658ac8c83421c455088f744a5c6f6634ef6e442784da0d6c3f2666b33b3a80a1fb027ebbd07dbc2498ddb614e7dd1e3d0b4c515a4293efa6c6cd42857ca00c4208eac931f0b8e3ace01d901c75511ebc1f63fe66ab4c1dc2c9977897c378c021dc440bfdd69f9cb951f47b8455732404aefbae71662c0ab425986d8afbfbaeb128f63521486c04a258da8150f318c752899b7cae3cd9de67080d0636b8b07dcd286bd")
	o, err := Decode(upp)
	if err != nil {
		t.Errorf("upp can't be decoded: %v", err)
	}

	c := o.(*ChainedUPP)
	if uuid.MustParse("4f6b64a7-a5c9-4837-86c0-0d32bc8e03c0") != c.Uuid {
		t.Errorf("uuid does not match")
	}
	hash, _ := base64.StdEncoding.DecodeString("lmjNczf0vBzd+pi6WL9eWllxZ4ate8Ju0uOxWx83SjA=")
	if bytes.Compare(hash, c.Payload) == 0 {
		t.Errorf("hash does not match")
	}
}

func TestCreateSignedMessage(t *testing.T) {
	digest := sha256.Sum256([]byte{'1'})
	upp, err := protocol.Sign(testName, digest[:], Signed)
	if err != nil {
		t.Errorf("signing failed: %v", err)
	}
	log.Printf("E: %s", expectedSigned)
	log.Printf("R: %s", hex.EncodeToString(upp[:len(upp)-64]))
	if expectedSigned != hex.EncodeToString(upp[:len(upp)-64]) {
		t.Errorf("upp encoding wrong")
	}
}

func TestCreateChainedMessage(t *testing.T) {
	previousSignature := make([]byte, 64)
	for i := 0; i < 3; i++ {
		digest := sha256.Sum256([]byte{byte(i + 1)})
		upp, err := protocol.Sign(testName, digest[:], Chained)
		if err != nil {
			t.Errorf("signing failed: %v", err)
		}
		expected, _ := hex.DecodeString(expectedChained[i])
		copy(expected[22:22+64], previousSignature)
		previousSignature = upp[len(upp)-64:]
		//log.Printf("%d S: %s", i, hex.EncodeToString(previousSignature))
		log.Printf("%d E: (%d) %s", i, len(expected), hex.EncodeToString(expected))
		log.Printf("%d R: (%d) %s", i, len(upp[:len(upp)-64]), hex.EncodeToString(upp[:len(upp)-64]))
		if !bytes.Equal(expected, upp[:len(upp)-64]) {
			t.Errorf("chain: %d: upp encoding wrong", i)
			return
		}
	}
}

func TestVerifyHashedMessage(t *testing.T) {
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

	if ecdsa.Verify(&vk, hsh, r, s) {
		log.Printf("signature okay")
	} else {
		t.Fatalf("signature not okay")
	}
}
