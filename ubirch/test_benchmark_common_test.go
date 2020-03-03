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
//This file contains common test and benchmark functions as well as defaults
package ubirch

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/google/uuid"
)

////Default Values////
// (for consistent defaults in benchmark/test table entries )
const (
	defaultName     = "A"
	defaultUUID     = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"                                                                                             //"f9038b4b-d3bc-47c9-9968-ea275f1b6de8"
	defaultPriv     = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	defaultPub      = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
	defaultLastSig  = "c03821e1bbabebce351044168c5016187829bcf60988869f4d0bd3e8a905d38fa0bde9269042ad062262dd6829cc8def9e71e10d0a527671ca5707a436b1f209"
	defaultDataSize = 200
)

//////Helper Functions//////

//loads a protocol context from a json file
func loadProtocolContext(p *Protocol, filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	}

	log.Printf("loaded protocol context")

	return nil

}

//saves a protocol context to a json file
func saveProtocolContext(p *Protocol, filename string) error {
	contextBytes, _ := json.Marshal(p)
	err := ioutil.WriteFile(filename, contextBytes, 0666)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	}

	log.Printf("saved protocol context")
	return nil

}

//Sets the passed protocol context to the passed values (name, UUID, private Key, last signature), passed as hex strings
func setProtocolContext(p *Protocol, Name string, UUID string, PrivKey string, LastSignature string) {

	id := uuid.MustParse(UUID)

	//Set private key (public key will automatically be calculated and set)
	privBytes, err := hex.DecodeString(PrivKey)
	if err != nil {
		panic(err)
	}
	err = p.Crypto.SetKey(Name, id, privBytes)
	if err != nil {
		panic(err)
	}

	//Set last Signature
	lastSigBytes, err := hex.DecodeString(LastSignature)
	if err != nil {
		panic(err)
	}
	p.Signatures[id] = lastSigBytes

}

//Generates reproducible pseudorandom data using a simple linear congruental generator.
//NEVER us this for something other than generating bogus input data.
func deterministicPseudoRandomBytes(seed int32, size int) []byte {
	block := make([]byte, size)
	//We use the same parameters used in the "simple" version of glibc's rand()
	//and simply fill the block with the generated numbers.
	for index := range block {
		seed = (1103515245*seed + 12345) & 0x7fffffff
		block[index] = byte(seed)
	}
	return block
}
