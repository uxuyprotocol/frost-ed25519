package helpers

import (
	"encoding/json"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type FKeyGenOutput struct {
	Secrets map[party.ID]*eddsa.SecretShare
	Shares  *eddsa.Public
}

type KeyGenOutState struct {
	PartyID   party.ID
	State     *state.State
	Output    *keygen.Output
	Message1  [][]byte
	Message2  [][]byte
	StateData []byte
}

type KeyGenOutStateJSON struct {
	PartyID   party.ID `json:"partyID"`
	State     []byte   `json:"state,omitempty"`
	Output    []byte   `json:"output,omitempty"`
	Message1  [][]byte `json:"message1,omitempty"`
	Message2  [][]byte `json:"message2,omitempty"`
	StateData []byte   `json:"stateData,omitempty"`
}

type MPCSignatureOutState struct {
	PartyID  party.ID
	State    *state.State
	Output   *sign.Output
	GroupKey *eddsa.PublicKey
	Message1 [][]byte
	Message2 [][]byte
}

func UnmarshalKGState(newState *state.State, data []byte) error {

	err := json.Unmarshal(data, &newState)
	if err != nil {
		return err
	}

	switch newState.GetRoundNumber() {
	case 1:
		var round0 keygen.Round1
		err = json.Unmarshal(newState.RoundData, &round0)
		if err != nil {
			fmt.Println(err)
			return err
		}
		newState.SetRound(&round0)
		return nil

	case 2:
		var round0 keygen.Round2
		err = json.Unmarshal(newState.RoundData, &round0)
		if err != nil {
			fmt.Println(err)
			return err
		}
		newState.SetRound(&round0)
		return nil

	case 3:
		var round0 keygen.Round2
		err = json.Unmarshal(newState.RoundData, &round0)
		if err != nil {
			fmt.Println(err)
			return err
		}
		newState.SetRound(&round0)
		return nil
	}

	return fmt.Errorf("unknown round number: %d", newState.GetRoundNumber())

}

// SetOutput 改变 output 指针指向
func (s *KeyGenOutState) SetOutput(o *keygen.Output) {
	s.Output = o
}

func MarshalKGOutState(s *KeyGenOutState) ([]byte, error) {

	sdata, err := json.Marshal(s.State)
	if err != nil {
		return nil, err
	}
	s.StateData = sdata

	opdata, err := s.Output.MarshalJSON()
	var jsonData = KeyGenOutStateJSON{
		PartyID:   s.PartyID,
		State:     sdata,
		Output:    opdata,
		Message1:  s.Message1,
		Message2:  s.Message2,
		StateData: sdata,
	}

	return json.Marshal(jsonData)
}

func UnmarshalKGOutState(s *KeyGenOutState, data []byte) error {

	var jsonData KeyGenOutStateJSON
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		return err
	}

	var estate state.State
	err = UnmarshalKGState(&estate, jsonData.StateData)
	if err != nil {
		return err
	}

	s.State = &estate

	fmt.Println("out.....", len(jsonData.Output))
	if s.Output == nil || len(jsonData.Output) > 100 {
		var output keygen.Output
		err = output.UnmarshalJSON(jsonData.Output)
		s.Output = &output
	}

	s.Message1 = jsonData.Message1
	s.Message2 = jsonData.Message2
	s.StateData = jsonData.StateData
	s.PartyID = jsonData.PartyID

	return err
}

//
//func UnmarshalRound(roundNum int, data []byte)(state.Round, error) {
//	switch roundNum {
//	case 1:
//		var round0 keygen.Round1
//		err := json.Unmarshal(data, &round0)
//		return &round0, err
//	case 2:
//		var round0 keygen.Round1
//		err := json.Unmarshal(data, &round0)
//		return &round0, err
//
//}

// ResetKeygenOutputPointee 设置指针...
func ResetKeygenOutputPointee(state *KeyGenOutState) {
	o := state.State.GetRound().GetOutput().(*keygen.Output)
	state.Output = o
}
