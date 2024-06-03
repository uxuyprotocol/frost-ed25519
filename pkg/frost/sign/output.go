package sign

import "github.com/uxuyprotocol/frost-ed25519/pkg/eddsa"

type Output struct {
	Signature *eddsa.Signature
}
