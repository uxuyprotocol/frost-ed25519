package sign

import (
	"github.com/uxuyprotocol/frost-ed25519/pkg/internal/scalar"
	"github.com/uxuyprotocol/frost-ed25519/pkg/messages"
	"github.com/uxuyprotocol/frost-ed25519/pkg/state"
)

func (round *Round0) ProcessMessage(*messages.Message) *state.Error {
	return nil
}

func (round *Round0) GenerateMessages() ([]*messages.Message, *state.Error) {
	selfParty := round.Parties[round.SelfID()]

	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&round.d)
	selfParty.Di.ScalarBaseMult(&round.d)

	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&round.e)
	selfParty.Ei.ScalarBaseMult(&round.e)

	msg := messages.NewSign1(round.SelfID(), &selfParty.Di, &selfParty.Ei)

	return []*messages.Message{msg}, nil
}

func (round *Round0) NextRound() state.Round {
	return &Round1{round}
}

func (round *Round0) GetOutput() interface{} {
	return round.Output
}
