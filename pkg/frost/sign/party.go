package sign

import (
	"encoding/json"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

// A signer represents the state we store for one particular
// co-signer. It can safely be reset once a signature has
// been generated, or an abort was detected.
type signer struct {
	// signer's additive share of the Public key.
	// It is multiplied by the party's Lagrange coefficient
	// so the we do need to do so later.
	Public ristretto.Element

	// Di = [di]•B
	// Ei = [ei]•B
	Di, Ei ristretto.Element

	// Ri = Di + [ρ] Ei
	// This is a share of the nonce R
	Ri ristretto.Element

	// Pi = ρ = H(i, Message, B)
	// This is the 'rho' from the paper
	Pi ristretto.Scalar

	// Zi = z = d + (e • ρ) + 𝛌 • s • c
	// This is the share of the final signature
	Zi ristretto.Scalar
}

// Reset sets all values to default.
// The party is no longer usable since the public key is deleted.
func (signer *signer) Reset() {
	zero := ristretto.NewScalar()
	identity := ristretto.NewIdentityElement()

	signer.Ei.Set(identity)
	signer.Di.Set(identity)

	signer.Ri.Set(identity)

	signer.Pi.Set(zero)
	signer.Zi.Set(zero)
}

type signerJSON struct {
	Public []byte `json:"public"`
	Di     []byte `json:"di"`
	Ei     []byte `json:"ei"`
	Ri     []byte `json:"ri"`
	Pi     []byte `json:"pi"`
	Zi     []byte `json:"zi"`
}

func (signer *signer) MarshalJSON() ([]byte, error) {

	//rInital := signer.Ri.PointInited()

	b1 := signer.Ri.Bytes()
	fmt.Println(len(b1), b1, signer.Ri.CheckPointInited())

	rawjson := signerJSON{
		Public: signer.Public.Bytes(),
		Di:     signer.Di.Bytes(),
		Ei:     signer.Ei.Bytes(),
		Ri:     signer.Ri.Bytes(),
		Pi:     signer.Pi.Bytes(),
		Zi:     signer.Zi.Bytes(),
	}

	return json.Marshal(&rawjson)
}

func (signer *signer) UnmarshalJSON(data []byte) error {
	var rawjson signerJSON
	err := json.Unmarshal(data, &rawjson)
	if err != nil {
		return err
	}
	var public = ristretto.NewIdentityElement()
	var di = ristretto.NewIdentityElement()
	var ei = ristretto.NewIdentityElement()
	var ri = ristretto.NewIdentityElement()
	var pi = ristretto.NewScalar()
	var zi = ristretto.NewScalar()
	pub, err := public.SetCanonicalBytes(rawjson.Public)
	if err != nil {
		return err
	}
	d, err := di.SetCanonicalBytes(rawjson.Di)
	if err != nil {
		return err
	}
	e, err := ei.SetCanonicalBytes(rawjson.Ei)
	if err != nil {
		return err
	}
	r, err := ri.SetCanonicalBytes(rawjson.Ri)
	if err != nil {
		return err
	}
	p, err := pi.SetCanonicalBytes(rawjson.Pi)
	if err != nil {
		return err
	}
	z1, err := zi.SetCanonicalBytes(rawjson.Zi)
	if err != nil {
		return err
	}
	signer.Public = *pub
	signer.Pi = *p
	signer.Zi = *z1
	signer.Ei = *e
	signer.Ri = *r
	signer.Pi = *pi
	signer.Di = *d
	return nil
}
