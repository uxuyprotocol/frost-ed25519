package state

import (
	"encoding/json"
	"errors"

	"github.com/uxuyprotocol/frost-ed25519/pkg/frost/party"
	"github.com/uxuyprotocol/frost-ed25519/pkg/messages"
)

type BaseRound struct {
	selfID   party.ID
	partyIDs party.IDSlice
}

func NewBaseRound(selfID party.ID, partyIDs party.IDSlice) (*BaseRound, error) {
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("PartyIDs should contain selfID")
	}
	return &BaseRound{
		selfID:   selfID,
		partyIDs: partyIDs,
	}, nil
}

func (r *BaseRound) ProcessMessage(*messages.Message) *Error {
	return nil
}

func (r BaseRound) SelfID() party.ID {
	return r.selfID
}

func (r BaseRound) PartyIDs() party.IDSlice {
	return r.partyIDs
}

type baseRoundJSON struct {
	SelfID   uint16   `json:"selfID"`
	PartyIDs []uint16 `json:"partIDs"`
}

func (r *BaseRound) MarshalJSON() ([]byte, error) {
	data := make([]uint16, len(r.partyIDs))
	for i, id := range r.partyIDs {
		data[i] = uint16(id)
	}
	return json.Marshal(baseRoundJSON{
		uint16(r.selfID),
		data,
	})
}

func (r *BaseRound) UnmarshalJSON(data []byte) error {

	var rawjson baseRoundJSON
	err := json.Unmarshal(data, &rawjson)
	if err != nil {
		return err
	}

	slice := make([]party.ID, len(rawjson.PartyIDs))
	for i, id := range rawjson.PartyIDs {
		slice[i] = party.ID(id)
	}

	r.selfID = party.ID(rawjson.SelfID)
	r.partyIDs = slice

	return nil
}
