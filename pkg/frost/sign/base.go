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
	Round0 struct {
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
	Round1 struct {
		*Round0
	}
	Round2 struct {
		*Round1
	}
)

func (round *Round0) MarshalRound() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (round *Round0) UnmarshalRound(data []byte) (state.Round, error) {
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

	round := &Round0{
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

func (round *Round0) Reset() {
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

func (round *Round0) AcceptedMessageTypes() []messages.MessageType {
	return []messages.MessageType{
		messages.MessageTypeNone,
		messages.MessageTypeSign1,
		messages.MessageTypeSign2,
	}
}

type Round0JSON struct {
	Base           []byte               `json:"base,omitempty"`
	Messages       []byte               `json:"messages,omitempty"`
	Parties        map[party.ID]*signer `json:"parties,omitempty"`
	GroupKey       []byte               `json:"group_key,omitempty"`
	SecretKeyShare []byte               `json:"secret_key_share,omitempty"`
	E              []byte               `json:"e_scalar,omitempty"`
	D              []byte               `json:"d_scalar,omitempty"`
	C              []byte               `json:"c_scalar,omitempty"`
	R              []byte               `json:"r_scalar,omitempty"`
	Output         []byte               `json:"output,omitempty"`
}

func (round *Round0) MarshalJSON() ([]byte, error) {

	baseData, err := round.BaseRound.MarshalJSON()
	if err != nil {
		return nil, err
	}

	sec := round.SecretKeyShare.Bytes()
	e := round.e.Bytes()
	d := round.d.Bytes()
	c := round.C.Bytes()

	gk, err := round.GroupKey.MarshalJSON()

	//fmt.Println(round.R.String())
	//fmt.Println(round.R.BytesEd25519())

	//r, err := round.R.MarshalText()
	//if err != nil {
	//	return nil, err
	//}

	var jsonData = Round0JSON{
		Base:           baseData,
		Messages:       round.Message,
		Parties:        round.Parties,
		GroupKey:       gk,
		SecretKeyShare: sec,
		E:              e,
		D:              d,
		C:              c,
		//R:              r,
	}
	var sigData []byte
	if round.Output.Signature != nil {
		sigData = round.Output.Signature.ToEd25519()
		jsonData.Output = sigData
	}

	return json.Marshal(&jsonData)
}

func (round *Round0) UnmarshalJSON(data []byte) error {
	var rawJson Round0JSON
	err := json.Unmarshal(data, &rawJson)
	if err != nil {
		return err
	}

	var base state.BaseRound
	err = base.UnmarshalJSON(rawJson.Base)
	if err != nil {
		return err
	}

	var gk eddsa.PublicKey
	err = gk.UnmarshalJSON(rawJson.GroupKey)
	if err != nil {
		return err
	}

	var out Output
	err = out.Signature.UnmarshalBinary(rawJson.Output)
	if err != nil {
		return err
	}

	var sec = ristretto.NewScalar()
	sec, err = sec.SetCanonicalBytes(rawJson.SecretKeyShare)
	if err != nil {
		return err
	}
	var e = ristretto.NewScalar()
	e, err = e.SetCanonicalBytes(rawJson.E)
	if err != nil {
		return err
	}
	var d = ristretto.NewScalar()
	d, err = d.SetCanonicalBytes(rawJson.D)
	if err != nil {
		return err
	}
	var c = ristretto.NewScalar()
	c, err = c.SetCanonicalBytes(rawJson.C)
	if err != nil {
		return err
	}
	//var r ristretto.Element
	//err = r.UnmarshalText(rawJson.R)
	//if err != nil {
	//	return err
	//}

	round.BaseRound = &base
	round.Message = rawJson.Messages
	round.Parties = make(map[party.ID]*signer)
	round.GroupKey = gk
	round.SecretKeyShare = *sec
	round.e = *e
	round.d = *d
	round.C = *c
	//round.R = r
	round.Output = &out

	return err
}

func (round *Round1) MarshalJSON() ([]byte, error) {

	var Round0 = round.Round0
	data, err := json.Marshal(&Round0)
	return data, err
}

func (round *Round1) UnmarshalJSON(data []byte) error {
	var Round0 Round0
	err := json.Unmarshal(data, &Round0)
	if err != nil {
		return err
	}
	round.Round0 = &Round0
	return nil
}

func (round *Round2) MarshalJSON() ([]byte, error) {

	var Round1 = round.Round1
	data, err := json.Marshal(&Round1)
	return data, err
}

func (round *Round2) UnmarshalJSON(data []byte) error {
	var Round1 Round1
	err := json.Unmarshal(data, &Round1)
	if err != nil {
		return err
	}
	round.Round1 = &Round1
	return nil
}
