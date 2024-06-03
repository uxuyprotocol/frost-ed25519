package keygen

import (
	"errors"
	"fmt"

	"github.com/uxuyprotocol/frost-ed25519/pkg/eddsa"
	"github.com/uxuyprotocol/frost-ed25519/pkg/frost/party"
	"github.com/uxuyprotocol/frost-ed25519/pkg/messages"
	"github.com/uxuyprotocol/frost-ed25519/pkg/ristretto"
	"github.com/uxuyprotocol/frost-ed25519/pkg/state"
)

func (round *Round2) ProcessMessage(msg *messages.Message) *state.Error {
	var computedShareExp ristretto.Element
	computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

	id := msg.From
	shareExp := round.Commitments[id].Evaluate(round.SelfID().Scalar())

	fmt.Println("round2ProcessMessage...", id, msg.KeyGen2.Share, round.Commitments[id], round.SelfID())
	if computedShareExp.Equal(shareExp) != 1 {
		return state.NewError(id, errors.New("VSS failed to validate"))
	}
	round.Secret.Add(&round.Secret, &msg.KeyGen2.Share)

	// We can reset the share in the message now
	msg.KeyGen2.Share.Set(ristretto.NewScalar())

	return nil
}

func (round *Round2) GenerateMessages() ([]*messages.Message, *state.Error) {
	shares := make(map[party.ID]*ristretto.Element, round.PartyIDs().N())
	for _, id := range round.PartyIDs() {
		shares[id] = round.CommitmentsSum.Evaluate(id.Scalar())
	}
	round.Output.Public = &eddsa.Public{
		PartyIDs:  round.BaseRound.PartyIDs().Copy(),
		Threshold: round.Threshold,
		Shares:    shares,
		GroupKey:  eddsa.NewPublicKeyFromPoint(round.CommitmentsSum.Constant()),
	}
	round.Output.SecretKey = eddsa.NewSecretShare(round.SelfID(), &round.Secret)
	return nil, nil
}

func (round *Round2) NextRound() state.Round {
	return nil
}

func (round *Round2) MessageType() messages.MessageType {
	return messages.MessageTypeKeyGen2
}

func (round *Round2) GetOutput() interface{} {
	return round.Output
}
