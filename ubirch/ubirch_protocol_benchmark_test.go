package ubirch

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

////Default Values////
// (for consistent defaults in benchmark table entries )
const (
	defaultName     = "A"
	defaultUUID     = "f9038b4b-d3bc-47c9-9968-ea275f1b6de8"
	defaultPriv     = "10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	defaultPub      = "92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
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

//saves a protocol context from a json file
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

//////Benchmark Functions//////

func BenchmarkSign(b *testing.B) {
	//Define data for all benchmarks to run
	benchmarks := []struct {
		testDescription  string
		deviceName       string
		deviceUUID       string
		devicePrivateKey string
		deviceLastSig    string
		dataSizeBytes    int
		signProtocol     ProtocolType
	}{
		{"Plain-defaultSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, defaultDataSize, Plain},
		{"Signed-defaultSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, defaultDataSize, Signed},
		{"Chained-defaultSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, defaultDataSize, Chained},
		{"Chained-1KBSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024, Chained},
		{"Chained-100KBSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, 100 * 1024, Chained},
		{"Chained-1MBSize", defaultName, defaultUUID, defaultPriv, defaultLastSig, 1024 * 1024, Chained},
	}

	//Iterate over all benchmarks
	for _, bm := range benchmarks {
		//Create new crypto context
		context := &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
		p := &Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
		//Load reference data into context
		setProtocolContext(p, bm.deviceName, bm.deviceUUID, bm.devicePrivateKey, bm.deviceLastSig)
		//Generate pseudrandom input data
		inputData := deterministicPseudoRandomBytes(0, bm.dataSizeBytes)
		//Run the current benchmark
		b.Run(bm.testDescription, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoded, err := p.Sign(bm.deviceName, inputData, bm.signProtocol)
				if err != nil {
					b.Fatalf("Sign() failed with error %v", err)
				}
				_ = encoded
			}
		})
	}
}
