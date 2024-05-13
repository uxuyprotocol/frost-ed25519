package sign

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type (
	round0 struct {
		*state.BaseRound

		// Message is the message to be signed
		Message []byte

		// Parties maps IDs to a struct containing all intermediary data for each signer.
		Parties map[party.ID]*signer

		// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
		GroupKey       eddsa.PublicKey
		SecretKeyShare ristretto.Scalar

		// e and d are the scalars committed to in the first round
		e, d ristretto.Scalar

		// C = H(R, GroupKey, Message)
		C ristretto.Scalar
		// R = ∑ Ri
		R ristretto.Element

		Output *Output
	}
	round1 struct {
		*round0
	}
	round2 struct {
		*round1
	}
)

func (round *round0) MarshalRound() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (round *round0) UnmarshalRound(data []byte) (state.Round, error) {
	//TODO implement me
	panic("implement me")
}

func NewRound(partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (state.Round, *Output, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}
	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, errors.New("base.NewRound: not all parties of partyIDs are contained in shares")
	}

	baseRound, err := state.NewBaseRound(secret.ID, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}

	round := &round0{
		BaseRound: baseRound,
		Message:   message,
		Parties:   make(map[party.ID]*signer, partyIDs.N()),
		GroupKey:  *shares.GroupKey,
		Output:    &Output{},
	}

	// Setup parties
	for _, id := range partyIDs {
		var s signer
		if id == 0 {
			return nil, nil, errors.New("base.NewRound: id 0 is not valid")
		}
		originalShare := shares.Shares[id]
		lagrange, err := id.Lagrange(partyIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("base.NewRound: %w", err)
		}
		s.Public.ScalarMult(lagrange, originalShare)
		round.Parties[id] = &s
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := round.SelfID().Lagrange(partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}
	round.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	return round, round.Output, nil
}

func (round *round0) Reset() {
	zero := ristretto.NewScalar()
	one := ristretto.NewIdentityElement()

	round.Message = nil
	round.SecretKeyShare.Set(zero)

	round.e.Set(zero)
	round.d.Set(zero)
	round.C.Set(zero)
	round.R.Set(one)

	for id, p := range round.Parties {
		p.Reset()
		delete(round.Parties, id)
	}
	round.Output = nil
}

func (round *round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{
		messages.MessageTypeNone,
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}

//type round0JSON struct {
//	Base *state.BaseRound `json:"base"`
//
//	Threshold party.Size `json:"threshold"`
//
//	Secret ristretto.Scalar `json:"secret,omitempty"`
//
//	Polynomial *polynomial.Polynomial `json:"polynomial,omitempty"`
//
//	CommitmentsSum *polynomial.Exponent `json:"commitments_sum,omitempty"`
//
//	Commitments map[party.ID]*polynomial.Exponent `json:"commitments,omitempty"`
//
//	Output *Output `json:"output,omitempty"`
//}

func (round *round0) MarshalJSON() ([]byte, error) {

	return json.Marshal(round)

	//rawJson := round0JSON{
	//	round.BaseRound,
	//	round.Threshold,
	//	round.Secret,
	//	round.Polynomial,
	//	round.CommitmentsSum,
	//	round.Commitments,
	//	round.Output,
	//}
	//result, err := json.Marshal(&rawJson)
	//if err != nil {
	//	return nil, err
	//}
	//return result, nil
}

func (round *round0) UnmarshalJSON(data []byte) error {

	return json.Unmarshal(data, round)

	//var rawJson round0JSON
	//err := json.Unmarshal(data, &rawJson)
	//if err != nil {
	//	return err
	//}
	//
	////var baseRound *state.BaseRound
	////err := json.Unmarshal(rawJson.Base, &baseRound)
	//
	//*round = round0{
	//	BaseRound:      rawJson.Base,
	//	Threshold:      rawJson.Threshold,
	//	Secret:         rawJson.Secret,
	//	Polynomial:     rawJson.Polynomial,
	//	CommitmentsSum: rawJson.CommitmentsSum,
	//	Commitments:    rawJson.Commitments,
	//	Output:         rawJson.Output,
	//}
	//return nil
}
