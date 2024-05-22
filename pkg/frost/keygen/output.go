package keygen

import (
	"encoding/json"
	"github.com/uxuyprotocol/frost-ed25519/pkg/eddsa"
)

type Output struct {
	Public    *eddsa.Public
	SecretKey *eddsa.SecretShare
}

type outputJson struct {
	Public []byte `json:"public"`
	Secret []byte `json:"secret"`
}

func (o *Output) MarshalJSON() ([]byte, error) {

	if o.Public == nil || o.SecretKey == nil {
		return json.Marshal(outputJson{})
	}
	pdata, err := o.Public.MarshalJSON()
	sdata, err := o.SecretKey.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var jsonData = outputJson{
		pdata,
		sdata,
	}

	return json.Marshal(jsonData)
}

func (o *Output) UnmarshalJSON(data []byte) error {

	var jsonData outputJson
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		return err
	}

	if jsonData.Public == nil || jsonData.Secret == nil {
		return nil
	}
	var pub = new(eddsa.Public)
	err = pub.UnmarshalJSON(jsonData.Public)
	if err != nil {
		return err
	}

	var secret = new(eddsa.SecretShare)
	err = secret.UnmarshalJSON(jsonData.Secret)

	o.Public = pub
	o.SecretKey = secret
	return err

}
