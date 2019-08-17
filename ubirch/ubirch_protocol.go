package ubirch

import (
	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
)

type CryptoInterface interface {
	GenerateKeyPair() error
	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, data []byte, signature []byte) (bool, error)
}

type UbirchProtocolPacket struct {
	Version       uint8
	Uuid          uuid.UUID
	PrevSignature [64]byte `codec:",omitempty"`
	Type          uint8
	Payload       []byte
	Signature     [64]byte
}

type Protocol struct {
	CryptoInterface
	uid uuid.UUID
}

func (p *Protocol) Init() {

}

func (p *Protocol) KeyGenerate(name string, uid uuid.UUID) error {
	return nil
}

func (p *Protocol) Sign(name string, value []byte, protocol int) ([]byte, error) {
	//var mh codec.MsgpackHandle
	//
	//upp := UbirchProtocolPacket{
	//	Version:       uint8(protocol),
	//	Uuid:          p.uid,
	//	PrevSignature: [64]byte{},
	//	Type:          0,
	//	Payload:       value,
	//	Signature:     [64]byte{},
	//}
	//uppEncoded := codec.NewEncoderBytes(, &mh)
	//p.Sign()
	return nil, nil
}

func (p *Protocol) Verify(name string, value []byte, protocol int) ([]byte, error) {
	return nil, nil
}
