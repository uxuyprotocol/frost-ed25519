package messages

import (
	"encoding/binary"
	"errors"
)

var (
	ErrInvalidMessage = errors.New("invalid message")
)

type MessageType uint8

const (
	MessageTypeKeyGen1 MessageType = iota
	MessageTypeKeyGen2
	MessageTypeSign1
	MessageTypeSign2
)

const headerSize = 1 + 8

type Message struct {
	Type     MessageType
	From, To uint32
	KeyGen1  *KeyGen1
	KeyGen2  *KeyGen2
	Sign1    *Sign1
	Sign2    *Sign2
}

func (m *Message) BytesAppend(existing []byte) (data []byte, err error) {
	var header [headerSize]byte
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:5], m.From)
	binary.BigEndian.PutUint32(header[5:9], m.To)
	existing = append(existing, header[:]...)

	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			return m.KeyGen1.BytesAppend(existing)
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			return m.KeyGen2.BytesAppend(existing)
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			return m.Sign1.BytesAppend(existing)
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			return m.Sign2.BytesAppend(existing)
		}
	}

	return nil, errors.New("message does not contain any data")
}

func (m *Message) Size() int {
	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			return headerSize + m.KeyGen1.Size()
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			return headerSize + m.KeyGen2.Size()
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			return headerSize + m.Sign1.Size()
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			return headerSize + m.Sign2.Size()
		}
	}
	return -1
}

func (m *Message) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

func (m *Message) UnmarshalBinary(data []byte) error {
	msgType := MessageType(data[0])
	m.Type = msgType
	m.From = binary.BigEndian.Uint32(data[1:])
	m.To = binary.BigEndian.Uint32(data[5:])

	switch msgType {
	case MessageTypeKeyGen1:
		var keygen1 KeyGen1
		m.KeyGen1 = &keygen1
		return m.KeyGen1.UnmarshalBinary(data[headerSize:])

	case MessageTypeKeyGen2:
		var keygen2 KeyGen2
		m.KeyGen2 = &keygen2
		return m.KeyGen2.UnmarshalBinary(data[headerSize:])

	case MessageTypeSign1:
		var sign1 Sign1
		m.Sign1 = &sign1

		return m.Sign1.UnmarshalBinary(data[headerSize:])

	case MessageTypeSign2:
		var sign2 Sign2
		m.Sign2 = &sign2

		return m.Sign2.UnmarshalBinary(data[headerSize:])
	}
	return errors.New("message type not recognized")
}