package communication

import (
	"fmt"

	"github.com/uxuyprotocol/frost-ed25519/pkg/eddsa"
	"github.com/uxuyprotocol/frost-ed25519/pkg/frost"
	"github.com/uxuyprotocol/frost-ed25519/pkg/frost/keygen"
	"github.com/uxuyprotocol/frost-ed25519/pkg/frost/party"
	"github.com/uxuyprotocol/frost-ed25519/pkg/frost/sign"
	"github.com/uxuyprotocol/frost-ed25519/pkg/state"
)

// Handler holds the information for a certain Round by a participant.
// It makes it easier to work with the underlying Round interface.
type Handler struct {
	State *state.State
	Comm  Communicator
}

type (
	KeyGenHandler struct {
		*Handler
		Out *keygen.Output
	}

	SignHandler struct {
		*Handler
		Out *sign.Output
	}
)

// HandleMessage is a blocking function that exits
func (h *Handler) HandleMessage() {
	h.ProcessAll()

	for {
		select {
		case msg := <-h.Comm.Incoming():
			if msg == nil {
				continue
			}
			if err := h.State.HandleMessage(msg); err != nil {
				//fmt.Println("handle message", err)
			}
			h.ProcessAll()
		case <-h.State.Done():
			err := h.State.Err()
			if err != nil {
				//fmt.Println("done with err: ", err)
			}
			return
		}
	}
}

func (h *Handler) ProcessAll() {
	msgsOut := h.State.ProcessAll()

	for _, msg := range msgsOut {
		err := h.Comm.Send(msg)
		if err != nil {
			fmt.Println("process all", err)
		}
	}
}

func NewKeyGenHandler(comm Communicator, ID party.ID, IDs []party.ID, T party.Size) (*KeyGenHandler, error) {
	set := party.NewIDSlice(IDs)
	s, out, err := frost.NewKeygenState(ID, set, T, comm.Timeout())
	if err != nil {
		return nil, err
	}
	h := &Handler{
		State: s,
		Comm:  comm,
	}
	go h.HandleMessage()
	return &KeyGenHandler{
		Handler: h,
		Out:     out,
	}, nil
}

func NewSignHandler(comm Communicator, IDs []party.ID, secret *eddsa.SecretShare, public *eddsa.Public, message []byte) (*SignHandler, error) {
	set := party.NewIDSlice(IDs)
	s, out, err := frost.NewSignState(set, secret, public, message, comm.Timeout())
	if err != nil {
		return nil, err
	}
	h := &Handler{
		State: s,
		Comm:  comm,
	}
	go h.HandleMessage()
	return &SignHandler{
		Handler: h,
		Out:     out,
	}, nil
}
