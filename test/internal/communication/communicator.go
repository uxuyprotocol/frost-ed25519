package communication

import (
	"time"

	"github.com/uxuyprotocol/frost-ed25519/pkg/messages"
)

type Communicator interface {
	Send(msg *messages.Message) error

	Incoming() <-chan *messages.Message
	Done()
	Timeout() time.Duration
}
