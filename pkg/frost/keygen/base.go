package keygen

import (
	"encoding/json"
	"errors"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/internal/polynomial"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type (
	Round0 struct {
		*state.BaseRound

		// Threshold is the degree of the polynomial used for Shamir.
		// It is the number of tolerated party corruptions.
		Threshold party.Size

		// Secret is first set to the zero coefficient of the polynomial we send to the other parties.
		// Once all received shares are declared, they are summed here to produce the party's
		// final secret key.
		Secret ristretto.Scalar

		// Polynomial used to sample shares
		Polynomial *polynomial.Polynomial

		// CommitmentsSum is the sum of all commitments, we use it to compute public key shares
		CommitmentsSum *polynomial.Exponent

		// Commitments contains all other parties commitment polynomials
		Commitments map[party.ID]*polynomial.Exponent

		Output *Output
	}
	Round1 struct {
		*Round0
	}
	Round2 struct {
		*Round1
	}
)

func NewRound(selfID party.ID, partyIDs party.IDSlice, threshold party.Size) (state.Round, *Output, error) {
	N := partyIDs.N()

	if threshold == 0 {
		return nil, nil, errors.New("threshold must be at least 1, or a minimum of T+1=2 signers")
	}
	if threshold > N-1 {
		return nil, nil, errors.New("threshold must be at most N-1, or a maximum of T+1=N signers")
	}

	baseRound, err := state.NewBaseRound(selfID, partyIDs)
	if err != nil {
		return nil, nil, err
	}

	r := Round0{
		BaseRound:   baseRound,
		Threshold:   threshold,
		Commitments: make(map[party.ID]*polynomial.Exponent, N),
		Output:      &Output{},
	}

	return &r, r.Output, nil
}

func (round *Round0) Reset() {
	round.Secret.Set(ristretto.NewScalar())
	round.Polynomial.Reset()
	round.CommitmentsSum.Reset()
	for _, p := range round.Commitments {
		p.Reset()
	}
	round.Output = nil
}

// ---
// Messages
// ---

func (round *Round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{messages.MessageTypeNone, messages.MessageTypeKeyGen1, messages.MessageTypeKeyGen2}
}

type Round0JSON struct {
	Base *state.BaseRound `json:"base"`

	Threshold party.Size `json:"threshold"`

	Secret ristretto.Scalar `json:"secret,omitempty"`

	Polynomial *polynomial.Polynomial `json:"polynomial,omitempty"`

	CommitmentsSum *polynomial.Exponent `json:"commitments_sum,omitempty"`

	Commitments map[party.ID]*polynomial.Exponent `json:"commitments,omitempty"`

	Output *Output `json:"output,omitempty"`
}

func (round *Round0) MarshalJSON() ([]byte, error) {

	rawJson := Round0JSON{
		round.BaseRound,
		round.Threshold,
		round.Secret,
		round.Polynomial,
		round.CommitmentsSum,
		round.Commitments,
		round.Output,
	}
	result, err := json.Marshal(&rawJson)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (round *Round0) UnmarshalJSON(data []byte) error {
	var rawJson Round0JSON
	err := json.Unmarshal(data, &rawJson)
	if err != nil {
		return err
	}

	//var baseRound *state.BaseRound
	//err := json.Unmarshal(rawJson.Base, &baseRound)

	*round = Round0{
		BaseRound:      rawJson.Base,
		Threshold:      rawJson.Threshold,
		Secret:         rawJson.Secret,
		Polynomial:     rawJson.Polynomial,
		CommitmentsSum: rawJson.CommitmentsSum,
		Commitments:    rawJson.Commitments,
		Output:         rawJson.Output,
	}
	return nil
}

func (round *Round0) MarshalRound() ([]byte, error) {
	return json.Marshal(&round)
}

func (round *Round0) UnmarshalRound(data []byte) (state.Round, error) {
	var result state.Round
	err := json.Unmarshal(data, &result)
	return result, err

}

func (round *Round1) MarshalRound() ([]byte, error) {
	return json.Marshal(&round)
}

func (round *Round1) UnmarshalRound(data []byte) (state.Round, error) {
	var result state.Round
	err := json.Unmarshal(data, &result)
	return result, err

}

func (round *Round2) MarshalRound() ([]byte, error) {
	return json.Marshal(&round)
}

func (round *Round2) UnmarshalRound(data []byte) (state.Round, error) {
	var result state.Round
	err := json.Unmarshal(data, &result)
	return result, err

}

//
//func (round *Round1) MarshalJSON() ([]byte, error) {
//	return json.Marshal(round.Round0)
//}
//
//func (round *Round1) UnmarshalJSON(data []byte) error {
//	var Round0 Round0
//	err := json.Unmarshal(data, &Round0)
//	if err != nil {
//		return err
//	}
//	round.Round0 = &Round0
//	return nil
//}
//
//func (round *Round2) MarshalJSON() ([]byte, error) {
//	return json.Marshal(round.Round1)
//}
//
//func (round *Round2) UnmarshalJSON(data []byte) error {
//	var Round1 Round1
//	err := json.Unmarshal(data, &Round1)
//	if err != nil {
//		return err
//	}
//	round.Round1 = &Round1
//	return nil
//}
