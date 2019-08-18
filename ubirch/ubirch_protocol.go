package ubirch

import (
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
	"log"
)

type Crypto interface {
	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, value []byte) ([]byte, error)
}

type UbirchProtocolPacket struct {
	Version   uint8
	Uuid      uuid.UUID
	Type      uint8
	Payload   []byte
	Signature []byte
}

type UbirchProtocolPacketChained struct {
	Version       uint8
	Uuid          uuid.UUID
	PrevSignature []byte
	Type          uint8
	Payload       []byte
	Signature     []byte
}

type Protocol struct {
	Crypto
	Uuid uuid.UUID
}

func (p *Protocol) Init() {

}

func (p *Protocol) KeyGenerate(name string, uid uuid.UUID) error {
	return nil
}

func (p *Protocol) Sign(name string, value []byte, protocol int) ([]byte, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	upp := UbirchProtocolPacket{
		Version:   uint8(protocol),
		Uuid:      p.Uuid,
		Type:      0,
		Payload:   value,
		Signature: []byte{},
	}
	uppEncoded := make([]byte, 128)
	encoder := codec.NewEncoderBytes(&uppEncoded, &mh)
	err := encoder.Encode(upp)
	if err != nil {
		return nil, err
	}
	log.Print(hex.EncodeToString(uppEncoded))
	upp.Signature, err = p.Crypto.Sign(p.Uuid, uppEncoded[:len(uppEncoded)-2])
	if err != nil {
		return nil, err
	}
	log.Printf("%v", upp)
	encoder.ResetBytes(&uppEncoded)
	err = encoder.Encode(upp)
	if err != nil {
		return nil, err
	}
	return uppEncoded, nil
}

func (p *Protocol) Verify(name string, value []byte, protocol int) ([]byte, error) {
	return nil, nil
}
