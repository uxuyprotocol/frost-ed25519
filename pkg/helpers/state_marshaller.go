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
		var round0 keygen.Round0
		err = json.Unmarshal(newState.RoundData, &round0)
		if err != nil {
			fmt.Println(err)
			return err
		}
		newState.SetRound(&round0)
		return nil

	case 2:
		var round0 keygen.Round1
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

func MarshalKGOutState(s *KeyGenOutState) ([]byte, error) {

	sdata, err := json.Marshal(s.State)
	if err != nil {
		return nil, err
	}
	s.StateData = sdata
	return json.Marshal(s)
}

func UnmarshalKGOutState(s *KeyGenOutState, data []byte) error {

	err := json.Unmarshal(data, s)
	if err != nil {
		return err
	}

	err = UnmarshalKGState(s.State, s.StateData)
	return err
}
