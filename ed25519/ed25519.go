//package ed25519

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"strings"
)

//const maxN = 100
//
//type Secret struct {
//	ID     int    `json:"id"`
//	Secret string `json:"secret"`
//}
//
//type Shares struct {
//	T        int               `json:"t"`
//	GroupKey string            `json:"groupkey"`
//	Shares   map[string]string `json:"shares"`
//}

//type CombinedOutput struct {
//	Secrets map[string]Secret `json:"Secrets"`
//	Shares  Shares            `json:"Shares"`
//}

/*
// encode2String takes a slice of byte slices, encodes each to a base64 string,
// and joins them into a single comma-separated string.
func encode2String(data [][]byte) string {
	var base64Strings []string
	for _, bytes := range data {
		encoded := base64.StdEncoding.EncodeToString(bytes)
		base64Strings = append(base64Strings, encoded)
	}
	return strings.Join(base64Strings, ",")
}

// decode2Bytes takes a comma-separated string of base64-encoded data and
// decodes it back into a slice of byte slices.
func decode2Bytes(data string) ([][]byte, error) {
	base64Strings := strings.Split(data, ",")
	var bytesSlices [][]byte
	for _, str := range base64Strings {
		decodedBytes, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err // Handle error if decoding fails
		}
		bytesSlices = append(bytesSlices, decodedBytes)
	}
	return bytesSlices, nil
}

func SliceKeygen(t int, n int) string {

	var err error
	if (n > maxN) || (t >= n) {
		_ = fmt.Errorf("0<t<n<%v", maxN)
		return ""
	}

	partyIDs := helpers.GenerateSet(party.ID(n))

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// create a state for each party
	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, party.Size(t), 0)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	// Get the public data
	fmt.Println("Group Key:")
	id0 := partyIDs[0]
	if err = states[id0].WaitForError(); err != nil {
		fmt.Println(err)
		return ""
	}
	public := outputs[id0].Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println(err)
			return ""
		}
		shareSecret := outputs[id].SecretKey
		sharePublic := public.Shares[id]
		secrets[id] = shareSecret
		fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", id, shareSecret.Secret.Bytes(), sharePublic.Bytes())
	}

	// TODO: write JSON file, to take as input by CLI signer
	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	var slices [][]byte
	for _, id := range partyIDs {

		// 创建一个新的 map 用于存储过滤后的 secretShare
		filteredSecrets := make(map[party.ID]*eddsa.SecretShare)

		// 遍历原始的 secrets map
		for nid, secret := range secrets {
			// 如果ID不等于'2'，则将其添加到新的 map 中
			if nid == id {
				filteredSecrets[id] = secret
			}
		}

		filteredShares := make(map[party.ID]*ristretto.Element)
		filteredShares[id] = public.Shares[id]

		filteredPubs := &eddsa.Public{
			partyIDs,
			party.Size(t),
			filteredShares,
			public.GroupKey,
		}

		kgOutput := KeyGenOutput{
			Secrets: filteredSecrets,
			Shares:  filteredPubs,
		}
		var jsonData []byte
		jsonData, err = json.MarshalIndent(kgOutput, "", " ")
		if err != nil {
			fmt.Println(err)
			return ""
		}

		slices = append(slices, jsonData)

		gk := kgOutput.Shares.GroupKey.ToEd25519()
		fmt.Printf("groupkey____: %v\n", base64.StdEncoding.EncodeToString(gk))

	}

	fmt.Println("生成分片：-----------------------")
	fmt.Println(slices)

	var encodedKeys = encode2String(slices)
	return encodedKeys
}

func mergeJson(slices [][]byte) ([]byte, error) {
	combinedOutput := CombinedOutput{
		Secrets: make(map[string]Secret),
		Shares:  Shares{Shares: make(map[string]string)},
	}

	var err error
	for i := 0; i < len(slices); i++ {
		data := slices[i]

		var output CombinedOutput
		err = json.Unmarshal(data, &output)
		if err != nil {
			return nil, err
		}

		// Merge the secrets from each file
		for key, secret := range output.Secrets {
			combinedOutput.Secrets[key] = secret
		}

		// Merge the shares from each file
		for key, value := range output.Shares.Shares {
			combinedOutput.Shares.Shares[key] = value
		}

		// Update other fields if needed
		if combinedOutput.Shares.T == 0 {
			combinedOutput.Shares.T = output.Shares.T
			combinedOutput.Shares.GroupKey = output.Shares.GroupKey
		}
	}

	combinedJSON, err := json.MarshalIndent(combinedOutput, "", "  ")
	if err != nil {
		return nil, err
	}

	return combinedJSON, nil
}

func Signature(keys string, msg string) string {

	var err error
	slices, err := decode2Bytes(keys)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	message := []byte(msg)

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return ""
	}

	mjson, err := mergeJson(slices)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput helpers.FKeyGenOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	fmt.Println("json: --- ", string(mjson), err)

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	// get n and t from the keygen output
	var n party.Size
	var t party.Size

	n = kgOutput.Shares.PartyIDs.N()
	t = kgOutput.Shares.Threshold

	fmt.Printf("(t, n) = (%v, %v)\n", t, n)

	partyIDs := helpers.GenerateSet(n)

	secretShares := kgOutput.Secrets
	publicShares := kgOutput.Shares

	// structure holding parties' state and output
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*sign.Output{}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n)

	for _, id := range partyIDs {
		states[id], outputs[id], err = frost.NewSignState(partyIDs, secretShares[id], publicShares, message, 0)
		if err != nil {
			fmt.Println()
		}
	}

	pk := publicShares.GroupKey

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println(err)
			return ""
		}
	}

	id0 := partyIDs[0]
	sig := outputs[id0].Signature
	if sig == nil {
		fmt.Println("null signature")
		return ""
	}

	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
		fmt.Println("signature verification failed (ed25519)")
		return ""
	}

	if !pk.Verify(message, sig) {
		fmt.Println("signature verification failed")
		return ""
	}

	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
	sigValue, err := sig.MarshalBinary()
	sigb64 := base64.StdEncoding.EncodeToString(sigValue)
	fmt.Printf("Success: signature is\n%x\n", sigb64)

	pkjson, err := pk.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	fmt.Printf("pk: %s\n", string(pkjson))

	return sigb64

}

func VerifySignature(sigvalue string, groupKey string, msg string) bool {

	var pk eddsa.PublicKey
	MESSAGE := []byte(msg)

	pkJson := `"` + groupKey + `"`

	var err error
	err = pk.UnmarshalJSON([]byte(pkJson))
	//err = json.Unmarshal([]byte(groupKey), &pk)
	if err != nil {
		fmt.Printf("pk unmarshal err: %v\n", err)
		return false
	}

	sigData, err := base64.StdEncoding.DecodeString(sigvalue)
	var sig eddsa.Signature
	err = sig.UnmarshalBinary(sigData)
	if err != nil {
		fmt.Printf("sig unmarshal err: %v\n", err)
		return false
	}
	// validate using classic
	if !ed25519.Verify(pk.ToEd25519(), MESSAGE, sig.ToEd25519()) {
		fmt.Printf("验证签名失败")
		return false
	}
	// Validate using our own function
	if !pk.Verify(MESSAGE, &sig) {
		fmt.Printf("验证签名失败")
		return false
	}
	return true
}

// Key2KGPOutput 还原分片为 kgp
func Key2KGPOutput(partyId string, key string) (helpers.FKeyGenOutput, error) {
	// MPC 签名
	slices, err := decode2Bytes(key)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return helpers.FKeyGenOutput{}, fmt.Errorf("verify failed slices is nil")
	}

	mjson, err := mergeJson(slices)

	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput CombinedOutput

	var jsonData []byte = mjson
	//jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}

	fmt.Println("json: --- ", string(mjson), err)

	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}

	// get n and t from the keygen output
	var n party.Size
	var t party.Size

	n = party.Size(len(kgOutput.Shares.Shares) + 1)
	t = party.Size(len(kgOutput.Shares.Shares))

	fmt.Printf("(t, n) = (%v, %v)\n", t, n)

	allPartyIDs := helpers.GenerateSet(n)
	var partyIDs []party.ID
	for _, id := range allPartyIDs {
		if id.String() == partyId {
			partyIDs = append(partyIDs, id)
		}
	}
	if len(partyIDs) == 0 {
		return helpers.FKeyGenOutput{}, fmt.Errorf("party id %s not found", partyId)
	}
	partyID := partyIDs[0]

	secretStr := kgOutput.Secrets[partyId].Secret
	publicStr := kgOutput.Shares.Shares[partyId]
	secretB, err := base64.StdEncoding.DecodeString(secretStr)
	publicB, err := base64.StdEncoding.DecodeString(publicStr)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}

	var secret ristretto.Scalar
	var public ristretto.Element

	_, err = secret.SetCanonicalBytes(secretB)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}
	_, err = public.SetCanonicalBytes(publicB)
	if err != nil {
		fmt.Println(err)
		return helpers.FKeyGenOutput{}, err
	}

	secretShare := eddsa.SecretShare{
		ID:     partyID,
		Secret: secret,
		Public: public,
	}

	secretShares := map[party.ID]*eddsa.SecretShare{
		partyID: &secretShare,
	}

	shares := map[party.ID]*ristretto.Element{
		partyID: &public,
	}

	partySlice := party.IDSlice{
		partyID,
	}

	groupKeyStr := kgOutput.Shares.GroupKey
	var groupKey eddsa.PublicKey
	pkJson := `"` + groupKeyStr + `"`
	err = groupKey.UnmarshalJSON([]byte(pkJson))
	//err = json.Unmarshal([]byte(groupKey), &pk)
	if err != nil {
		fmt.Printf("groupkey unmarshal err: %v\n", err)
		return helpers.FKeyGenOutput{}, err
	}

	publicShares := eddsa.Public{
		partySlice,
		party.Size(1),
		shares,
		&groupKey,
	}

	kgp := helpers.FKeyGenOutput{
		Secrets: secretShares,
		Shares:  &publicShares,
	}
	return kgp, nil
}

func MPCPartSignV2(n int, keys []string, messageStr string) (string, error) {

	partyIDs := helpers.GenerateSet(party.Size(n))

	partyID1 := partyIDs[0]
	partyID2 := partyIDs[1]

	//var kgp helpers.FKeyGenOutput
	kgp1, err := Key2KGPOutput("1", keys[0])
	kgp2, err := Key2KGPOutput("2", keys[1])
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	secretShares1 := kgp1.Secrets
	publicShares1 := kgp1.Shares

	secretShares2 := kgp2.Secrets
	publicShares2 := kgp2.Shares

	ps := map[party.ID]*ristretto.Element{
		partyID1: publicShares1.Shares[partyID1],
		partyID2: publicShares2.Shares[partyID2],
	}

	publicShares := eddsa.Public{
		partyIDs,
		party.Size(2),
		ps,
		publicShares1.GroupKey,
	}

	message := []byte(messageStr)
	state1, output1, err := frost.NewSignState(partyIDs, secretShares1[partyID1], &publicShares, message, 0)

	state2, output2, err := frost.NewSignState(partyIDs, secretShares2[partyID2], &publicShares, message, 0)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n)
	msgs1, err := helpers.PartyRoutine(nil, state1)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	msgsOut1 = append(msgsOut1, msgs1...)

	msgs11, err := helpers.PartyRoutine(nil, state2)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	msgsOut1 = append(msgsOut1, msgs11...)

	msgs2, err := helpers.PartyRoutine(msgsOut1, state1)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	msgsOut2 = append(msgsOut2, msgs2...)

	msgs22, err := helpers.PartyRoutine(msgsOut1, state2)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	msgsOut2 = append(msgsOut2, msgs22...)

	msg3, err := helpers.PartyRoutine(msgsOut2, state1)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	msg33, err := helpers.PartyRoutine(msgsOut2, state2)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	sig1 := output1.Signature
	sig2 := output2.Signature

	fmt.Println(msg3, msg33)
	fmt.Printf("sig1: %v\n", sig1.ToEd25519())
	fmt.Printf("sig2: %v\n", sig2.ToEd25519())

	ver1 := sig1.Equal(sig2)
	fmt.Println("验证结果1", ver1)
	if ed25519.Verify(publicShares.GroupKey.ToEd25519(), message, sig1.ToEd25519()) {
		fmt.Println("签名结果1验证成功")
	}
	if ed25519.Verify(publicShares.GroupKey.ToEd25519(), message, sig2.ToEd25519()) {
		fmt.Println("签名结果2验证成功")
	}

	if publicShares.GroupKey.Verify(message, sig1) {
		fmt.Println("签名结果3验证成功")
	}

	if publicShares.GroupKey.Verify(message, sig2) {
		fmt.Println("签名结果4验证成功")
	}

	return "", nil
}

func unitTestVerifySignature(filename string) {
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("read file error: %v", err)
		return
	}
	// 定义结构体
	type Data struct {
		Keys      string `json:"keys"`
		GroupKey  string `json:"groupKey"`
		Msg       string `json:"msg"`
		Signature string `json:"signature"`
		Verify    bool   `json:"verify"`
	}
	// 解析 JSON
	var data []Data
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		fmt.Println("json parse Error:", err)
		return
	}

	for i, item := range data {
		//keys := item['keys'];
		groupKey := item.GroupKey
		msg := item.Msg
		signature := item.Signature

		verify := VerifySignature(signature, groupKey, msg)
		fmt.Println(i, verify)
		if verify != true {
			break
		}

	}
}

func mpcSigtest() {
	message := "test010101UUU"
	keys := []string{"ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAicThZQXdmd1g1QWxrOGx1Vm5wdHk2L2djQzRZYVc1bVpvQTRSdU4ybVZBMD0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiR1AxUzJ3Wmx6NGlpamhhUVBFV2hxMWhUNVF3U1RXeExVWHozN0ZFU1FnYz0iCiAgfQogfQp9", "ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAicEc0Vk00cTg2SVFFQ1FJS09uMG5mQzBIQXhIL0lCV1hkeGsrZXBNUHJnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiWEdiYlF5Nlh1SjNvdU1XL2tjZmFZT3lRYUNyWVNPYUdNaHRhNDBjSlZ5bz0iCiAgfQogfQp9"}

	s, e := MPCPartSignV2(2, keys, message)
	fmt.Println(s, e)

}
*/

func KeygenMsg2String(kMsg [][]byte) string {
	var result []string
	for _, msg := range kMsg {
		result = append(result, base64.StdEncoding.EncodeToString(msg))
	}
	return strings.Join(result, ",")
}

func KeygenString2Msg(kMsgStr string) [][]byte {

	var result [][]byte
	for _, msg := range strings.Split(kMsgStr, ",") {
		b, err := base64.StdEncoding.DecodeString(msg)
		if err != nil {
			fmt.Println("base64 decode error:", err)
			break
		}
		result = append(result, b)
	}
	return result
}

// SliceKeyGenRound0 keygen 阶段1 - 初始化 state
func SliceKeyGenRound0(n int, index int) (helpers.KeyGenOutState, []byte, error) {

	var err error

	partyIDs := helpers.GenerateSet(party.ID(n))
	partyID := partyIDs[index]

	// create a state for each party

	estate, output, err := frost.NewKeygenState(partyID, partyIDs, party.Size(n-1), 0)
	if err != nil {
		fmt.Println(err)
		return helpers.KeyGenOutState{}, nil, err
	}

	msgsOut1 := make([][]byte, 0, n)
	//msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	//round0
	msgs1, err := helpers.PartyRoutine(nil, estate)
	if err != nil {
		fmt.Println(err)
		return helpers.KeyGenOutState{}, nil, err
	}
	msgsOut1 = append(msgsOut1, msgs1...)

	result := helpers.KeyGenOutState{
		PartyID:  partyID,
		State:    estate,
		Output:   output,
		Message1: msgsOut1,
	}

	//TODO

	d, err := helpers.MarshalKGOutState(&result)
	var result2 helpers.KeyGenOutState
	err = helpers.UnmarshalKGOutState(&result2, d)
	fmt.Println(result, result2)

	return result, d, err
}

// SliceKeyGenRound1 生成密钥分片 round1
func SliceKeyGenRound1(index int, outStateData []byte, outState1 helpers.KeyGenOutState, yMessage string) (helpers.KeyGenOutState, []byte, error) {

	if len(yMessage) == 0 {
		return helpers.KeyGenOutState{}, nil, fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, outStateData)
	if err != nil {
		return helpers.KeyGenOutState{}, nil, err
	}

	if index == 0 {
		outState.Message1 = append(outState.Message1, yMsg...)
		outState1.Message1 = append(outState1.Message1, yMsg...)
	} else {
		outState.Message1 = append(yMsg, outState.Message1...)
		outState1.Message1 = append(yMsg, outState1.Message1...)
	}

	println("sround11: ----------------------------------------------")
	fmt.Println(outState1.Message1, outState1.State.RoundData, outState1.State)
	println("sround12: ----------------------------------------------")
	fmt.Println(outState.Message1, outState.State.RoundData, outState.State)
	println("sround end: ----------------------------------------------")

	msgs2, err := helpers.PartyRoutine(outState1.Message1, outState1.State)
	if err != nil {
		fmt.Println(err)
		return helpers.KeyGenOutState{}, nil, err
	}

	outState1.Message2 = append(outState1.Message2, msgs2...)

	msgs2, err = helpers.PartyRoutine(outState.Message1, outState.State)
	if err != nil {
		fmt.Println(err)
		return helpers.KeyGenOutState{}, nil, err
	}
	outState.Message2 = append(outState.Message2, msgs2...)

	d, err := helpers.MarshalKGOutState(&outState)
	var result2 helpers.KeyGenOutState
	err = helpers.UnmarshalKGOutState(&result2, d)
	fmt.Println(outState, result2)

	return outState1, d, err
}

// SliceKeyGenRound2 生成密钥分片 round2
func SliceKeyGenRound2(index int, outState1 helpers.KeyGenOutState, outStateData []byte, yMessage string) (helpers.KeyGenOutState, []byte, error) {

	if len(yMessage) == 0 {
		return helpers.KeyGenOutState{}, nil, fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, outStateData)
	if err != nil {
		return helpers.KeyGenOutState{}, nil, err
	}

	if index == 0 {
		outState.Message2 = append(outState.Message2, yMsg...)
	} else {
		outState.Message2 = append(yMsg, outState.Message2...)
	}

	//if index == 0 {
	//	outState1.Message2 = append(outState1.Message2, yMsg...)
	//} else {
	//	outState1.Message2 = append(yMsg, outState1.Message2...)
	//}

	//_, err = helpers.PartyRoutine(outState1.Message2, outState1.State)
	//if err != nil {
	//	fmt.Println(err)
	//	return helpers.KeyGenOutState{}, nil, err
	//}

	_, err = helpers.PartyRoutine(outState.Message2, outState.State)
	if err != nil {
		fmt.Println(err)
		return helpers.KeyGenOutState{}, nil, err
	}

	stateData2, err := helpers.MarshalKGOutState(&outState)
	err = helpers.UnmarshalKGOutState(&outState, stateData2)

	return outState1, stateData2, err
}

// DKGSlice 生成最终密钥分片分片
func DKGSlice(n int, oustateData []byte, outState1 helpers.KeyGenOutState) (string, error) {

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, oustateData)
	if err != nil {
		return "", err
	}

	//TODO:
	//outState = outState1

	// Get the public data
	estate := outState.State
	output := outState.Output
	partyID := outState.PartyID
	if err := estate.WaitForError(); err != nil {
		fmt.Println(err)
		return "", err
	}
	public := outState.Output.Public
	secrets := make(map[party.ID]*eddsa.SecretShare, n)
	groupKey := public.GroupKey
	fmt.Printf("  %x\n\n", groupKey.ToEd25519())

	shareSecret := output.SecretKey
	sharePublic := public.Shares[partyID]
	secrets[partyID] = shareSecret
	fmt.Printf("Party %d:\n  secret: %x\n  public: %x\n", partyID, shareSecret.Secret.Bytes(), sharePublic.Bytes())

	type KeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
	}

	partyIDs := helpers.GenerateSet(party.ID(n))
	filteredPubs := &eddsa.Public{
		partyIDs,
		party.Size(n - 1),
		public.Shares,
		public.GroupKey,
	}

	kgOutput := KeyGenOutput{
		Secrets: secrets,
		Shares:  filteredPubs,
	}
	var jsonData []byte
	jsonData, err = json.MarshalIndent(kgOutput, "", " ")
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	gk := kgOutput.Shares.GroupKey.ToEd25519()
	fmt.Printf("groupkey____: %v\n", base64.StdEncoding.EncodeToString(gk))

	slice := base64.StdEncoding.EncodeToString(jsonData)
	fmt.Println("生成分片：-----------------------\n------------------------", string(jsonData))
	return slice, nil

}

// MPCPartSignRound0 MPC 签名第一阶段 生成 state & output
func MPCPartSignRound0(n int, index int, key string, message string) (helpers.MPCSignatureOutState, error) {

	partyIDs := helpers.GenerateSet(party.Size(n))

	partyID := partyIDs[index]

	jsonData, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		fmt.Println(err)
		return helpers.MPCSignatureOutState{}, err
	}

	var kgp helpers.FKeyGenOutput
	err = json.Unmarshal(jsonData, &kgp)
	if err != nil {
		fmt.Println(err)
		return helpers.MPCSignatureOutState{}, err
	}

	secretShares := kgp.Secrets
	pshares := kgp.Shares

	ps := map[party.ID]*ristretto.Element{}
	for _, pid := range partyIDs {
		ps[pid] = pshares.Shares[pid]
	}

	publicShares := eddsa.Public{
		partyIDs,
		party.Size(1),
		ps,
		pshares.GroupKey,
	}

	messageB := []byte(message)
	estate, output, err := frost.NewSignState(partyIDs, secretShares[partyID], &publicShares, messageB, 0)

	if err != nil {
		fmt.Println(err)
		return helpers.MPCSignatureOutState{}, err
	}

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n)
	result := helpers.MPCSignatureOutState{
		PartyID:  partyID,
		State:    estate,
		Output:   output,
		GroupKey: publicShares.GroupKey,
		Message1: msgsOut1,
		Message2: msgsOut2,
	}

	msgs, err := helpers.PartyRoutine(nil, estate)
	result.Message1 = msgs
	if err != nil {
		fmt.Println(err)
		return result, err
	}

	return result, nil
}

func MPCPartSignRound1(index int, inputState helpers.MPCSignatureOutState, yMessage string) (helpers.MPCSignatureOutState, error) {

	estate := inputState.State

	if len(yMessage) == 0 {
		return inputState, fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	if index == 0 {
		inputState.Message1 = append(inputState.Message1, yMsg...)
	} else {
		inputState.Message1 = append(yMsg, inputState.Message1...)
	}

	msgs, err := helpers.PartyRoutine(inputState.Message1, estate)
	if err != nil {
		fmt.Println(err)
		return inputState, err
	}

	inputState.Message2 = msgs
	return inputState, nil
}

func MPCPartSignRound2(index int, inputState helpers.MPCSignatureOutState, yMessage string, message string) (string, error) {

	estate := inputState.State

	if len(yMessage) == 0 {
		return "", fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	if index == 0 {
		inputState.Message2 = append(inputState.Message2, yMsg...)
	} else {
		inputState.Message2 = append(yMsg, inputState.Message2...)
	}

	_, err := helpers.PartyRoutine(inputState.Message2, estate)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	sig := inputState.Output.Signature

	fmt.Printf("sig: %v\n", sig.ToEd25519())

	if ed25519.Verify(inputState.GroupKey.ToEd25519(), []byte(message), sig.ToEd25519()) {
		fmt.Println("签名结果验证成功")
	}

	sigResult := base64.StdEncoding.EncodeToString(sig.ToEd25519())
	return sigResult, nil
}

func VerifySignature(groupKey *eddsa.PublicKey, message string, signature string) bool {

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println(err)
		return false
	}
	verify := ed25519.Verify(groupKey.ToEd25519(), []byte(message), sig)
	return verify
}

// dpkTest 分布式分片生成
func dpkTest() {
	// client round0
	cstate, cstateData, err := SliceKeyGenRound0(2, 0)
	if err != nil {
		fmt.Println("kg1...", err)
		return
	}

	// server round0
	sstate, sstateData, err := SliceKeyGenRound0(2, 1)
	if err != nil {
		fmt.Println("kg2...", err)
		return
	}

	var cstate2 helpers.KeyGenOutState
	var sstate2 helpers.KeyGenOutState

	err = helpers.UnmarshalKGOutState(&cstate2, cstateData)
	if err != nil {
		fmt.Println("kg3...", err)
		return
	}
	err = helpers.UnmarshalKGOutState(&sstate2, sstateData)
	if err != nil {
		fmt.Println("kg4...", err)
		return
	}

	smsg1 := KeygenMsg2String(sstate.Message1)
	smsg11 := KeygenMsg2String(sstate2.Message1)
	if smsg1 != smsg11 {
		fmt.Println("kg5...", smsg1, smsg11)
		return
	}

	cstate, cstateData, err = SliceKeyGenRound1(0, cstateData, cstate, smsg1)
	if err != nil {
		fmt.Println("kg6...", err)
		return
	}

	err = helpers.UnmarshalKGOutState(&cstate2, cstateData)
	if err != nil {
		fmt.Println("kg7...", err)
		return
	}

	// server round1
	cmsg1 := KeygenMsg2String(cstate.Message1)
	cmsg11 := KeygenMsg2String(cstate2.Message1)
	if cmsg1 != cmsg11 {
		fmt.Println("kg8...", cmsg1, cmsg11)
		return
	}

	sstate, sstateData, err = SliceKeyGenRound1(1, sstateData, sstate, cmsg1)
	if err != nil {
		fmt.Println("kg9...", err)
		return
	}

	err = helpers.UnmarshalKGOutState(&sstate2, sstateData)
	if err != nil {
		fmt.Println("kg10...", err)
		return
	}
	err = helpers.UnmarshalKGOutState(&cstate2, cstateData)
	if err != nil {
		fmt.Println("kg11...", err)
		return
	}

	//err = helpers.UnmarshalKGOutState(&cstate1, cstate)
	//err = helpers.UnmarshalKGOutState(&sstate1, sstate)

	//err = json.Unmarshal(cstate, &cstate1)
	//err = json.Unmarshal(sstate, &sstate1)
	//if err != nil {
	//	fmt.Println("kg4...", err)
	//	return
	//}

	// client round2

	//cstateData, err = helpers.MarshalKGOutState(&cstate)
	//sstateData, err = helpers.MarshalKGOutState(&sstate)
	//if err != nil {
	//	fmt.Println("kg5...", err)
	//	return
	//}

	smsg1 = KeygenMsg2String(sstate.Message2)
	smsg11 = KeygenMsg2String(sstate2.Message2)
	if smsg1 != smsg11 {
		fmt.Println("kg12 error...", smsg1, smsg11)
		//return
	}
	cstate, cstateData, err = SliceKeyGenRound2(0, cstate, cstateData, smsg1)
	if err != nil {
		fmt.Println("kg13...", err)
		return
	}

	err = helpers.UnmarshalKGOutState(&cstate2, cstateData)
	if err != nil {
		fmt.Println("kg14...", err)
		return
	}

	// server round2
	cmsg1 = KeygenMsg2String(cstate.Message2)
	cmsg11 = KeygenMsg2String(cstate2.Message2)
	if cmsg1 != cmsg11 {
		fmt.Println("kg15 error...", cmsg1, cmsg11)
		//return
	}
	sstate, sstateData, err = SliceKeyGenRound2(1, sstate, sstateData, cmsg1)
	if err != nil {
		fmt.Println("kg16...", err)
		return
	}

	// client gen slice
	cslice, err := DKGSlice(2, cstateData, cstate)
	if err != nil {
		fmt.Println("kg17...", err)
		return
	}
	fmt.Println("client slice: ", cslice)

	// client gen slice
	sslice, err := DKGSlice(2, sstateData, sstate)
	if err != nil {
		fmt.Println("kg18...", err)
		return
	}
	fmt.Println("server slice: ", sslice)
	//end

	//// client round1
	//smsg1 := KeygenMsg2String(sstate1.Message1)
	//cstate, err = SliceKeyGenRound1(0, cstate, smsg1)
	//if err != nil {
	//	fmt.Println("kg3...", err)
	//	return
	//}
	//
	//// server round1
	//cmsg1 := KeygenMsg2String(cstate1.Message1)
	//sstate, err = SliceKeyGenRound1(1, sstate, cmsg1)
	//if err != nil {
	//	fmt.Println("kg4...", err)
	//	return
	//}

	//err = helpers.UnmarshalKGOutState(&cstate1, cstate)
	//err = helpers.UnmarshalKGOutState(&sstate1, sstate)
	//
	////err = json.Unmarshal(cstate, &cstate1)
	////err = json.Unmarshal(sstate, &sstate1)
	//if err != nil {
	//	fmt.Println("kg4...", err)
	//	return
	//}
	//
	//// client round2
	//smsg1 = KeygenMsg2String(sstate1.Message2)
	//cstate, err = SliceKeyGenRound2(0, cstate, smsg1)
	//if err != nil {
	//	fmt.Println("kg5...", err)
	//	return
	//}
	//
	//// server round2
	//cmsg1 = KeygenMsg2String(cstate1.Message2)
	//sstate, err = SliceKeyGenRound2(1, sstate, cmsg1)
	//if err != nil {
	//	fmt.Println("kg6...", err)
	//	return
	//}
	//
	//err = json.Unmarshal(cstate, &cstate1)
	//err = json.Unmarshal(sstate, &sstate1)
	//if err != nil {
	//	fmt.Println("kg4...", err)
	//	return
	//}
	//
	//// client gen slice
	//cslice, err := DKGSlice(2, cstate1)
	//if err != nil {
	//	fmt.Println("kg7...", err)
	//	return
	//}
	//fmt.Println("client slice: ", cslice)
	//
	//// client gen slice
	//sslice, err := DKGSlice(2, sstate1)
	//if err != nil {
	//	fmt.Println("kg8...", err)
	//	return
	//}
	//fmt.Println("server slice: ", sslice)

}

// sigtest 分布式签名测试
func sigtest() {

	clientSlice := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAiTERSL0xUZGNtUk9oSzZaOTFZbHc4NHpIbFlYTERKZ1hiUDFXd2c1R29RMD0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJTS0VwaFlFOVdGL0dGUDJRcy8yVWt3TGRFK0VVdjZKRDMyUW5iUTV0aFE0PSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiNk9xNklGOVZHK2RkUUJQY3A2M2M5cWROZGZQTklkMnlRT1l4dUdleGNCTT0iLAogICAiMiI6ICJVb09UNWViYjJRN0w2UEViT1B0MTJtRTNJeE9FVVU4SkpNNkFkTWRPOFJNPSIKICB9CiB9Cn0="
	serverSlice := "ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAibmc3TTY2OWpabWx5QjF4L05VbUJMRGtNdGkyd2FENFhrRS93WkhSMkJBWT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJTS0VwaFlFOVdGL0dGUDJRcy8yVWt3TGRFK0VVdjZKRDMyUW5iUTV0aFE0PSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiNk9xNklGOVZHK2RkUUJQY3A2M2M5cWROZGZQTklkMnlRT1l4dUdleGNCTT0iLAogICAiMiI6ICJVb09UNWViYjJRN0w2UEViT1B0MTJtRTNJeE9FVVU4SkpNNkFkTWRPOFJNPSIKICB9CiB9Cn0="

	message := "MessageUXUY_*()&(*^&*(^*^"

	//client round0
	cstate, err := MPCPartSignRound0(2, 0, clientSlice, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round0
	sstate, err := MPCPartSignRound0(2, 1, serverSlice, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	//client round1
	smsg1 := KeygenMsg2String(sstate.Message1)
	cstate, err = MPCPartSignRound1(0, cstate, smsg1)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round1
	cmsg1 := KeygenMsg2String(cstate.Message1)
	sstate, err = MPCPartSignRound1(1, sstate, cmsg1)
	if err != nil {
		fmt.Println(err)
		return
	}

	//client round2
	smsg2 := KeygenMsg2String(sstate.Message2)
	sig1, err := MPCPartSignRound2(0, cstate, smsg2, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round1
	cmsg2 := KeygenMsg2String(cstate.Message2)
	sig2, err := MPCPartSignRound2(1, sstate, cmsg2, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("sig1: ", sig1)
	fmt.Println("sig2: ", sig2)

	//sigE1, err := base64.StdEncoding.DecodeString(sig1)
	//sigE2, err := base64.StdEncoding.DecodeString(sig2)

	cgk := cstate.GroupKey
	sgk := cstate.GroupKey

	//verify1 := ed25519.Verify(cgk.ToEd25519(), []byte(message), sigE1)
	//verify2 := ed25519.Verify(sgk.ToEd25519(), []byte(message), sigE2)

	verify1 := VerifySignature(cgk, message, sig1)
	verify2 := VerifySignature(sgk, message, sig2)

	fmt.Println("verify1: ", verify1)
	fmt.Println("verify2: ", verify2)

}

func main() {
	//keygenDemo(2, 3)

	//keygenDemoV2(2, 3)

	//slices := SliceKeygen(1, 2)
	//sigs := Signature(slices, "message222")
	//fmt.Println("验证结果", sigs)

	//msg := "msg112233*&"
	//keys := SliceKeygen(1, 2)
	//fmt.Printf("keys: %v\n", keys)
	//sig1 := Signature(keys, msg)
	//fmt.Printf("[sig1: %v\n]", sig1)

	//keysList := strings.Split(keys, ",")
	//key1 := strings.Join(keysList, ",")
	//key2 := strings.Join(keysList[:2], ",")
	//sig2 := Signature(keysList[1], msg)
	//sig3 := Signature(key1, msg)
	//sig4 := Signature(key2, msg)
	//fmt.Printf("[sig1: %v\n, sig2: %v\n, sig3: %v\n, sig4: %v\n]", sig1, sig2, sig3, sig4)

	//验签
	//verify1 := VerifySignature("7lRgQEXJEojpyfBmccb0mC8BzNxKYgI0hlgFqQ+xaGf58ch2acpYByT1wqrqP2FlXWmGG+Clv6r5MH3PwnZOBQ==", "3uwHRj188SR7aMQy1LPV0OiigWaZbNp3piwsOWAN7nw=", msg)
	//verify2 := VerifySignature("QqrcpHytkdvxITKoZf3y+TjFUXnPSyYh1nSBOpKhEQBu22mIgyyVKO/sy4yM1HUKW7yq2Noro7al+m5rAzTbBw==", "3uwHRj188SR7aMQy1LPV0OiigWaZbNp3piwsOWAN7nw=", msg)
	//fmt.Printf("验证结果: [%v, %v]", verify1, verify2)

	//verify := VerifySignature(sig, "lFmgvmJr1wQkdnbVZr410gaOHCZbO42xQxVY1DvZnmE=", msg)
	//unitTestVerifySignature("./ed25519_demo.txt")

	//fromAddress := "4xJ3bqT3zsAqBngPoCwtYhJiZ6Ax9riBCdTHKjUUZ5gr"
	//toAddress := "2vvzNTow58DMDZhxyp5SNTxfGXAdHehXY8nyFuRHFy4W"
	//keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAid1lLMHNqQUVmcmNlWU1yaUh1NmNtUnkzQzFrY1ZHMTIrR1pXVGg5STd3WT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAieWxib2haaTV5N3NkblRyanBLYnlxeXNFd3JPRnZ6UUFCTTdJKzRkZlRqMD0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiL0gyVmM4QS9jVS9pREd5OEduenhkcDE2aS90NlVmYzdXUTV3L2VPdHZnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiYk1zWDM3Wks5OWtYdFYyMmZ4MkZ3ZjYzMUlpMkY5eUY5K3FKKzA5MVZBaz0iCiAgfQogfQp9"
	//groupKey := "aM0x+P7wVth5KM9fs6WLjikWYnZQp8mCJYoUzzW/NUo="
	//message := buildSolanaTransactionMsg(fromAddress, toAddress, 333)
	//sig := solanaTransactionTest(keys, message)
	//fmt.Printf("sig: %s\n", sig)
	//verify := VerifySignature(sig, groupKey, message)
	//fmt.Printf("verify: %v\n", verify)

	//mpcSigtest()

	dpkTest()

	//sigtest()
}
