package ed25519

//package main

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
func SliceKeyGenRound0(n int, index int) ([]byte, error) {

	fmt.Println("round0----------------------------------------------")
	var err error

	partyIDs := helpers.GenerateSet(party.ID(n))
	partyID := partyIDs[index]

	// create a state for each party

	estate, output, err := frost.NewKeygenState(partyID, partyIDs, party.Size(n-1), 0)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	msgsOut1 := make([][]byte, 0, n)
	//msgsOut2 := make([][]byte, 0, n*(n-1)/2)

	//round0
	msgs1, err := helpers.PartyRoutine(nil, estate)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	msgsOut1 = append(msgsOut1, msgs1...)

	result := helpers.KeyGenOutState{
		PartyID:  partyID,
		State:    estate,
		Output:   output,
		Message1: msgsOut1,
	}

	d, err := helpers.MarshalKGOutState(&result)
	var result2 helpers.KeyGenOutState
	err = helpers.UnmarshalKGOutState(&result2, d)
	//fmt.Println(result, result2)

	fmt.Println("round0 end----------------------------------------------")
	return d, err
}

// SliceKeyGenRound1 生成密钥分片 round1
func SliceKeyGenRound1(index int, outStateData []byte, yMessage string) ([]byte, error) {

	fmt.Println("round1----------------------------------------------")
	if len(yMessage) == 0 {
		return nil, fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, outStateData)
	if err != nil {
		return nil, err
	}

	if index == 0 {
		outState.Message1 = append(outState.Message1, yMsg...)

	} else {
		outState.Message1 = append(yMsg, outState.Message1...)

	}

	msgs2, err := helpers.PartyRoutine(outState.Message1, outState.State)
	fmt.Println("end part1...", outState.Output.Public, outState.Output.SecretKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	outState.Message2 = append(outState.Message2, msgs2...)

	d, err := helpers.MarshalKGOutState(&outState)
	var result2 helpers.KeyGenOutState
	err = helpers.UnmarshalKGOutState(&result2, d)
	//fmt.Println(outState, result2)

	fmt.Println("round1 end----------------------------------------------")
	return d, err
}

// SliceKeyGenRound2 生成密钥分片 round2
func SliceKeyGenRound2(index int, outStateData []byte, yMessage string) ([]byte, error) {

	fmt.Println("round2----------------------------------------------")
	if len(yMessage) == 0 {
		return nil, fmt.Errorf("remoteMessage is empty")
	}

	yMsg := KeygenString2Msg(yMessage)

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, outStateData)
	if err != nil {
		return nil, err
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

	helpers.ResetKeygenOutputPointee(&outState)

	_, err = helpers.PartyRoutine(outState.Message2, outState.State)
	fmt.Println("end part2...", outState.Output.Public, outState.Output.SecretKey)
	if err != nil {
		fmt.Println(err)
		//return helpers.KeyGenOutState{}, nil, err
	}

	stateData2, err := helpers.MarshalKGOutState(&outState)
	err = helpers.UnmarshalKGOutState(&outState, stateData2)

	fmt.Println("round2 end----------------------------------------------")
	return stateData2, err
}

// DKGSlice 生成最终密钥分片分片
func DKGSlice(n int, outStateData []byte) (string, error) {

	var outState helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&outState, outStateData)
	if err != nil {
		return "", err
	}

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
func MPCPartSignRound0(n int, index int, key string, message string) ([]byte, error) {

	msgB, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, err
	}
	message = string(msgB)
	partyIDs := helpers.GenerateSet(party.Size(n))

	partyID := partyIDs[index]

	jsonData, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var kgp helpers.FKeyGenOutput
	err = json.Unmarshal(jsonData, &kgp)
	if err != nil {
		fmt.Println(err)
		return nil, err
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
		return nil, err
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
		return nil, err
	}

	//fmt.Println("round0-------------------------------")
	statedata, err := json.Marshal(&result)
	//var state2 helpers.MPCSignatureOutState
	//err = json.Unmarshal(statedata, &state2)
	//statedata2, err := json.Marshal(&state2)
	//fmt.Println(statedata)
	//fmt.Println(statedata2)

	//fmt.Println("round0 end-------------------------------")

	return statedata, err
}

func MPCPartSignRound1(index int, inputStateData []byte, yMessage string) ([]byte, error) {

	var inputState helpers.MPCSignatureOutState
	err := json.Unmarshal(inputStateData, &inputState)
	if err != nil {
		return nil, err
	}
	estate := inputState.State

	if len(yMessage) == 0 {
		return nil, fmt.Errorf("remoteMessage is empty")
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
		return nil, err
	}

	inputState.Message2 = msgs
	data, err := json.Marshal(&inputState)

	return data, err
}

func MPCPartSignRound2(index int, inputStateData []byte, yMessage string, message string) (string, error) {

	msgB, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	message = string(msgB)
	var inputState helpers.MPCSignatureOutState
	err = json.Unmarshal(inputStateData, &inputState)
	if err != nil {
		return "", err
	}

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

	helpers.ResetSignOutputPointee(&inputState)
	_, err = helpers.PartyRoutine(inputState.Message2, estate)
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

func VerifySignature(groupKey []byte, message string, signature string) bool {

	msgB, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		fmt.Println("message decode error", err)
		return false
	}
	message = string(msgB)
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println(err)
		return false
	}
	verify := ed25519.Verify(groupKey, []byte(message), sig)
	return verify
}

// GetGroupkeyFromSlice 从分片中获取组公钥 GroupKey
func GetGroupkeyFromSlice(slice string) ([]byte, error) {

	sliceData, err := base64.StdEncoding.DecodeString(slice)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	var kg helpers.FKeyGenOutput
	err = json.Unmarshal(sliceData, &kg)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return kg.Shares.GroupKey.ToEd25519(), nil

}

// GetMessageFromKeygenOutData  从 output 中获取 Message 信息
func GetMessageFromKeygenOutData(kgOutputData []byte, msgIndex int) (string, error) {
	var state helpers.KeyGenOutState
	err := helpers.UnmarshalKGOutState(&state, kgOutputData)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	if msgIndex == 0 {
		msg := KeygenMsg2String(state.Message1)
		return msg, nil
	} else {
		msg := KeygenMsg2String(state.Message2)
		return msg, nil
	}
}

// GetMessageFromSignOutData 从 output 中获取 message 信息
func GetMessageFromSignOutData(kgOutputData []byte, msgIndex int) (string, error) {
	var state helpers.MPCSignatureOutState
	err := json.Unmarshal(kgOutputData, &state)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	if msgIndex == 0 {
		msg := KeygenMsg2String(state.Message1)
		return msg, nil
	} else {
		msg := KeygenMsg2String(state.Message2)
		return msg, nil
	}
}

func Base642UTF8String(b64String string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64String)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(data), nil
}

// GetSolAddress 生成 Solana 地址
//func GetSolAddress(publicKey []byte) string {
//	account := solana.PublicKeyFromBytes(publicKey)
//	return account.String()
//}

// dpkTest 分布式分片生成
func dpkTest() {
	// client round0
	cstateData, err := SliceKeyGenRound0(2, 0)
	if err != nil {
		fmt.Println("kg1...", err)
		return
	}

	// server round0
	sstateData, err := SliceKeyGenRound0(2, 1)
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

	smsg1 := KeygenMsg2String(sstate2.Message1)

	cstateData, err = SliceKeyGenRound1(0, cstateData, smsg1)
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
	cmsg1 := KeygenMsg2String(cstate2.Message1)

	sstateData, err = SliceKeyGenRound1(1, sstateData, cmsg1)
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

	smsg1 = KeygenMsg2String(sstate2.Message2)

	cstateData, err = SliceKeyGenRound2(0, cstateData, smsg1)
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
	cmsg1 = KeygenMsg2String(cstate2.Message2)
	sstateData, err = SliceKeyGenRound2(1, sstateData, cmsg1)
	if err != nil {
		fmt.Println("kg16...", err)
		return
	}

	// client gen slice
	cslice, err := DKGSlice(2, cstateData)
	if err != nil {
		fmt.Println("kg17...", err)
		return
	}
	fmt.Println("client slice: ", cslice)

	// client gen slice
	sslice, err := DKGSlice(2, sstateData)
	if err != nil {
		fmt.Println("kg18...", err)
		return
	}
	fmt.Println("server slice: ", sslice)
	//end

}

// sigtest 分布式签名测试
func sigtest() {

	clientSlice := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAiL2lnTHBoR3MxeDFOUVZ3b29LZ1IyN29Tc1dTRzdVQjM3K0UvUmJDTGJnWT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJNdXc1TG9Tdmd0RkhGbExmVmVWTk5HeVVDV3pObTFVajNremRSKzBwTEZjPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiTkF6OVYrRGc3T3lDN3ZyUmNoenNQTWtveU9iM0plZ2dSVFZ3eHJuY0hYOD0iLAogICAiMiI6ICJKQWh3bldsUGZJUHJuNkFRZURyRmJpNWpvVmxrcm9kVWdoWEsyM3B2OTJ3PSIKICB9CiB9Cn0="
	serverSlice := "ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiSUNmNThvNjg0UkVZRWFYYW5kelVUc2ZIamRhYkdBRllPcWxlVURFR1VBRT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJNdXc1TG9Tdmd0RkhGbExmVmVWTk5HeVVDV3pObTFVajNremRSKzBwTEZjPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiTkF6OVYrRGc3T3lDN3ZyUmNoenNQTWtveU9iM0plZ2dSVFZ3eHJuY0hYOD0iLAogICAiMiI6ICJKQWh3bldsUGZJUHJuNkFRZURyRmJpNWpvVmxrcm9kVWdoWEsyM3B2OTJ3PSIKICB9CiB9Cn0="

	//message := "MessageUXUY_*()&(*^&*(^*^"
	message := "hello"

	groupK1, err := GetGroupkeyFromSlice(clientSlice)
	groupK2, err := GetGroupkeyFromSlice(serverSlice)
	if err != nil {
		fmt.Println("kg15...", err)
		return
	}
	fmt.Println("groupK1:", groupK1)
	fmt.Println("groupK2:", groupK2)

	//client round0
	cstatedata, err := MPCPartSignRound0(2, 0, clientSlice, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round0
	sstatedata, err := MPCPartSignRound0(2, 1, serverSlice, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	var cstate helpers.MPCSignatureOutState
	var sstate helpers.MPCSignatureOutState

	err = json.Unmarshal(cstatedata, &cstate)
	err = json.Unmarshal(sstatedata, &sstate)
	if err != nil {
		fmt.Println(err)
		return
	}

	smsg11, err := GetMessageFromSignOutData(sstatedata, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("------------round0-----------------")
	fmt.Println(cstatedata)
	fmt.Println(len(cstatedata), smsg11)

	//client round1
	smsg1 := KeygenMsg2String(sstate.Message1)
	fmt.Println(smsg1, smsg11)
	cstatedata, err = MPCPartSignRound1(0, cstatedata, smsg11)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(cstatedata, &cstate)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round1
	cmsg1 := KeygenMsg2String(cstate.Message1)
	sstatedata, err = MPCPartSignRound1(1, sstatedata, cmsg1)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Unmarshal(sstatedata, &sstate)
	if err != nil {
		fmt.Println(err)
		return
	}

	//client round2
	smsg2 := KeygenMsg2String(sstate.Message2)
	sig1, err := MPCPartSignRound2(0, cstatedata, smsg2, message)
	if err != nil {
		fmt.Println(err)
		return
	}

	//server round1
	cmsg2 := KeygenMsg2String(cstate.Message2)
	sig2, err := MPCPartSignRound2(1, sstatedata, cmsg2, message)
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

	verify1 := VerifySignature(cgk.ToEd25519(), message, sig1)
	verify2 := VerifySignature(sgk.ToEd25519(), message, sig2)

	fmt.Println("verify1: ", verify1)
	fmt.Println("verify2: ", verify2)

}

func arr2bytes(data []uint8) []byte {
	bytes := make([]byte, len(data))

	for i, v := range data {
		bytes[i] = byte(v)
	}
	return bytes
}
func dkg_cs_test() {

	cstateData, err := SliceKeyGenRound0(2, 0)
	if err != nil {
		fmt.Println("kg1...", err)
		return
	}

	fmt.Println("round0-----------------------------")
	fmt.Println(len(cstateData), cstateData, err)
	fmt.Println("round0 end-----------------------------")

	coutdata1 := []int8{123, 34, 112, 97, 114, 116, 121, 73, 68, 34, 58, 34, 49, 34, 44, 34, 115, 116, 97, 116, 101, 34, 58, 34, 101, 121, 74, 104, 89, 50, 78, 108, 99, 72, 82, 108, 90, 70, 82, 53, 99, 71, 86, 122, 73, 106, 111, 105, 81, 86, 70, 74, 80, 83, 73, 115, 73, 110, 74, 108, 89, 50, 86, 112, 100, 109, 86, 107, 84, 87, 86, 122, 99, 50, 70, 110, 90, 88, 77, 105, 79, 110, 116, 57, 76, 67, 74, 120, 100, 87, 86, 49, 90, 83, 73, 54, 87, 49, 48, 115, 73, 110, 74, 118, 100, 87, 53, 107, 84, 110, 86, 116, 89, 109, 86, 121, 73, 106, 111, 120, 76, 67, 74, 121, 98, 51, 86, 117, 90, 67, 73, 54, 73, 109, 86, 53, 83, 109, 108, 90, 87, 69, 53, 115, 83, 87, 112, 118, 97, 86, 112, 89, 98, 69, 116, 108, 98, 72, 66, 89, 90, 85, 99, 120, 86, 70, 90, 87, 82, 110, 66, 85, 77, 110, 66, 71, 89, 122, 66, 115, 100, 86, 70, 116, 97, 71, 112, 105, 98, 69, 112, 76, 86, 87, 116, 111, 84, 109, 70, 86, 79, 88, 78, 106, 77, 50, 104, 78, 85, 107, 86, 119, 97, 49, 112, 115, 82, 84, 108, 81, 85, 48, 108, 122, 83, 87, 53, 83, 98, 50, 78, 116, 86, 110, 112, 104, 82, 122, 108, 122, 87, 107, 78, 74, 78, 107, 108, 113, 82, 87, 108, 77, 81, 48, 112, 54, 87, 108, 100, 79, 101, 86, 112, 89, 85, 87, 108, 80, 97, 85, 112, 118, 85, 109, 112, 115, 78, 85, 119, 119, 100, 51, 108, 97, 77, 109, 82, 111, 90, 69, 85, 49, 98, 108, 70, 117, 99, 71, 108, 86, 86, 51, 66, 85, 90, 86, 100, 87, 84, 108, 70, 86, 90, 71, 112, 87, 98, 108, 112, 54, 85, 84, 78, 66, 99, 108, 70, 89, 81, 107, 104, 84, 101, 88, 82, 49, 85, 109, 120, 107, 82, 108, 112, 73, 90, 69, 53, 81, 85, 48, 108, 122, 83, 87, 53, 67, 100, 109, 74, 73, 98, 72, 86, 105, 77, 106, 70, 119, 87, 86, 100, 51, 97, 85, 57, 115, 99, 50, 108, 87, 98, 88, 66, 81, 86, 106, 70, 74, 77, 108, 111, 121, 84, 84, 78, 85, 97, 107, 90, 51, 84, 48, 82, 111, 83, 108, 90, 71, 97, 69, 49, 78, 86, 85, 90, 118, 89, 109, 49, 83, 83, 108, 112, 70, 79, 88, 66, 90, 77, 70, 90, 67, 84, 108, 99, 53, 100, 69, 57, 72, 84, 110, 78, 78, 86, 86, 85, 48, 87, 84, 74, 97, 77, 50, 82, 54, 77, 71, 108, 77, 81, 48, 112, 73, 90, 68, 66, 83, 86, 70, 74, 87, 85, 107, 86, 105, 98, 107, 73, 49, 86, 110, 112, 97, 84, 70, 90, 114, 87, 110, 104, 108, 82, 109, 104, 68, 86, 86, 86, 74, 100, 50, 74, 84, 99, 51, 90, 84, 82, 88, 66, 82, 83, 122, 78, 67, 81, 108, 100, 86, 84, 109, 70, 107, 86, 109, 119, 49, 85, 86, 90, 97, 100, 107, 115, 119, 82, 108, 112, 81, 85, 48, 112, 107, 84, 69, 78, 75, 97, 109, 73, 121, 77, 88, 82, 104, 87, 70, 74, 48, 87, 108, 99, 49, 77, 71, 77, 120, 79, 88, 112, 107, 86, 122, 66, 112, 84, 50, 108, 75, 81, 108, 70, 86, 97, 70, 112, 78, 97, 108, 74, 114, 89, 85, 90, 115, 86, 107, 57, 89, 97, 122, 78, 79, 83, 70, 86, 52, 89, 108, 100, 107, 82, 107, 49, 70, 77, 86, 90, 87, 86, 51, 66, 112, 87, 108, 104, 107, 98, 108, 82, 114, 98, 71, 112, 83, 97, 109, 120, 97, 87, 106, 70, 71, 97, 109, 82, 86, 98, 51, 74, 97, 86, 108, 69, 121, 89, 106, 66, 115, 86, 49, 78, 112, 100, 72, 74, 104, 77, 107, 90, 121, 86, 85, 100, 97, 97, 108, 90, 115, 97, 68, 82, 86, 82, 70, 85, 49, 85, 107, 86, 48, 83, 109, 78, 85, 86, 110, 104, 107, 98, 71, 104, 112, 86, 49, 90, 107, 81, 108, 112, 72, 83, 110, 74, 79, 82, 48, 90, 114, 87, 108, 82, 107, 81, 107, 57, 85, 83, 110, 70, 79, 77, 107, 53, 68, 83, 87, 108, 51, 97, 87, 73, 122, 86, 106, 66, 106, 83, 70, 89, 119, 83, 87, 112, 119, 78, 48, 108, 117, 81, 106, 70, 90, 98, 88, 104, 119, 87, 88, 108, 74, 78, 109, 74, 117, 86, 110, 78, 105, 81, 51, 100, 112, 89, 122, 74, 87, 97, 109, 78, 116, 86, 106, 66, 74, 97, 110, 66, 49, 90, 70, 100, 52, 99, 50, 90, 89, 77, 68, 48, 105, 102, 81, 61, 61, 34, 44, 34, 111, 117, 116, 112, 117, 116, 34, 58, 34, 101, 121, 74, 119, 100, 87, 74, 115, 97, 87, 77, 105, 79, 109, 53, 49, 98, 71, 119, 115, 73, 110, 78, 108, 89, 51, 74, 108, 100, 67, 73, 54, 98, 110, 86, 115, 98, 72, 48, 61, 34, 44, 34, 109, 101, 115, 115, 97, 103, 101, 49, 34, 58, 91, 34, 65, 81, 65, 66, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 77, 75, 85, 49, 54, 120, 109, 87, 72, 66, 99, 47, 90, 114, 81, 75, 115, 66, 90, 113, 104, 104, 86, 116, 56, 108, 57, 102, 87, 122, 83, 117, 87, 81, 119, 48, 48, 112, 69, 88, 77, 65, 75, 65, 65, 72, 89, 50, 52, 100, 104, 89, 85, 57, 121, 55, 52, 117, 49, 109, 103, 69, 48, 77, 85, 85, 106, 98, 101, 119, 103, 78, 73, 99, 70, 57, 89, 103, 81, 99, 117, 74, 43, 101, 84, 54, 111, 73, 86, 74, 43, 107, 107, 97, 107, 80, 102, 99, 86, 88, 120, 80, 53, 57, 68, 75, 73, 113, 53, 113, 118, 88, 98, 89, 87, 65, 100, 98, 107, 52, 97, 100, 101, 55, 65, 57, 50, 106, 55, 99, 66, 34, 93, 44, 34, 115, 116, 97, 116, 101, 68, 97, 116, 97, 34, 58, 34, 101, 121, 74, 104, 89, 50, 78, 108, 99, 72, 82, 108, 90, 70, 82, 53, 99, 71, 86, 122, 73, 106, 111, 105, 81, 86, 70, 74, 80, 83, 73, 115, 73, 110, 74, 108, 89, 50, 86, 112, 100, 109, 86, 107, 84, 87, 86, 122, 99, 50, 70, 110, 90, 88, 77, 105, 79, 110, 116, 57, 76, 67, 74, 120, 100, 87, 86, 49, 90, 83, 73, 54, 87, 49, 48, 115, 73, 110, 74, 118, 100, 87, 53, 107, 84, 110, 86, 116, 89, 109, 86, 121, 73, 106, 111, 120, 76, 67, 74, 121, 98, 51, 86, 117, 90, 67, 73, 54, 73, 109, 86, 53, 83, 109, 108, 90, 87, 69, 53, 115, 83, 87, 112, 118, 97, 86, 112, 89, 98, 69, 116, 108, 98, 72, 66, 89, 90, 85, 99, 120, 86, 70, 90, 87, 82, 110, 66, 85, 77, 110, 66, 71, 89, 122, 66, 115, 100, 86, 70, 116, 97, 71, 112, 105, 98, 69, 112, 76, 86, 87, 116, 111, 84, 109, 70, 86, 79, 88, 78, 106, 77, 50, 104, 78, 85, 107, 86, 119, 97, 49, 112, 115, 82, 84, 108, 81, 85, 48, 108, 122, 83, 87, 53, 83, 98, 50, 78, 116, 86, 110, 112, 104, 82, 122, 108, 122, 87, 107, 78, 74, 78, 107, 108, 113, 82, 87, 108, 77, 81, 48, 112, 54, 87, 108, 100, 79, 101, 86, 112, 89, 85, 87, 108, 80, 97, 85, 112, 118, 85, 109, 112, 115, 78, 85, 119, 119, 100, 51, 108, 97, 77, 109, 82, 111, 90, 69, 85, 49, 98, 108, 70, 117, 99, 71, 108, 86, 86, 51, 66, 85, 90, 86, 100, 87, 84, 108, 70, 86, 90, 71, 112, 87, 98, 108, 112, 54, 85, 84, 78, 66, 99, 108, 70, 89, 81, 107, 104, 84, 101, 88, 82, 49, 85, 109, 120, 107, 82, 108, 112, 73, 90, 69, 53, 81, 85, 48, 108, 122, 83, 87, 53, 67, 100, 109, 74, 73, 98, 72, 86, 105, 77, 106, 70, 119, 87, 86, 100, 51, 97, 85, 57, 115, 99, 50, 108, 87, 98, 88, 66, 81, 86, 106, 70, 74, 77, 108, 111, 121, 84, 84, 78, 85, 97, 107, 90, 51, 84, 48, 82, 111, 83, 108, 90, 71, 97, 69, 49, 78, 86, 85, 90, 118, 89, 109, 49, 83, 83, 108, 112, 70, 79, 88, 66, 90, 77, 70, 90, 67, 84, 108, 99, 53, 100, 69, 57, 72, 84, 110, 78, 78, 86, 86, 85, 48, 87, 84, 74, 97, 77, 50, 82, 54, 77, 71, 108, 77, 81, 48, 112, 73, 90, 68, 66, 83, 86, 70, 74, 87, 85, 107, 86, 105, 98, 107, 73, 49, 86, 110, 112, 97, 84, 70, 90, 114, 87, 110, 104, 108, 82, 109, 104, 68, 86, 86, 86, 74, 100, 50, 74, 84, 99, 51, 90, 84, 82, 88, 66, 82, 83, 122, 78, 67, 81, 108, 100, 86, 84, 109, 70, 107, 86, 109, 119, 49, 85, 86, 90, 97, 100, 107, 115, 119, 82, 108, 112, 81, 85, 48, 112, 107, 84, 69, 78, 75, 97, 109, 73, 121, 77, 88, 82, 104, 87, 70, 74, 48, 87, 108, 99, 49, 77, 71, 77, 120, 79, 88, 112, 107, 86, 122, 66, 112, 84, 50, 108, 75, 81, 108, 70, 86, 97, 70, 112, 78, 97, 108, 74, 114, 89, 85, 90, 115, 86, 107, 57, 89, 97, 122, 78, 79, 83, 70, 86, 52, 89, 108, 100, 107, 82, 107, 49, 70, 77, 86, 90, 87, 86, 51, 66, 112, 87, 108, 104, 107, 98, 108, 82, 114, 98, 71, 112, 83, 97, 109, 120, 97, 87, 106, 70, 71, 97, 109, 82, 86, 98, 51, 74, 97, 86, 108, 69, 121, 89, 106, 66, 115, 86, 49, 78, 112, 100, 72, 74, 104, 77, 107, 90, 121, 86, 85, 100, 97, 97, 108, 90, 115, 97, 68, 82, 86, 82, 70, 85, 49, 85, 107, 86, 48, 83, 109, 78, 85, 86, 110, 104, 107, 98, 71, 104, 112, 86, 49, 90, 107, 81, 108, 112, 72, 83, 110, 74, 79, 82, 48, 90, 114, 87, 108, 82, 107, 81, 107, 57, 85, 83, 110, 70, 79, 77, 107, 53, 68, 83, 87, 108, 51, 97, 87, 73, 122, 86, 106, 66, 106, 83, 70, 89, 119, 83, 87, 112, 119, 78, 48, 108, 117, 81, 106, 70, 90, 98, 88, 104, 119, 87, 88, 108, 74, 78, 109, 74, 117, 86, 110, 78, 105, 81, 51, 100, 112, 89, 122, 74, 87, 97, 109, 78, 116, 86, 106, 66, 74, 97, 110, 66, 49, 90, 70, 100, 52, 99, 50, 90, 89, 77, 68, 48, 105, 102, 81, 61, 61, 34, 125}

	msg1, err := GetMessageFromKeygenOutData(cstateData, 0)
	fmt.Println("kg002", msg1, err)

	bytes := make([]byte, len(coutdata1))
	fmt.Println("clientout2", len(bytes))
	for i, v := range coutdata1 {
		bytes[i] = byte(v)
	}
	msg2, err := GetMessageFromKeygenOutData(bytes, 0)
	fmt.Println("kg003", msg2, err)
	fmt.Println("round0 msg end-----------------------------")

}

func mpc_cs_test() {
	outdata1 := []uint8{123, 34, 80, 97, 114, 116, 121, 73, 68, 34, 58, 49, 44, 34, 115, 116, 97, 116, 101, 34, 58, 34, 101, 121, 74, 104, 89, 50, 78, 108, 99, 72, 82, 108, 90, 70, 82, 53, 99, 71, 86, 122, 73, 106, 111, 105, 81, 88, 100, 82, 80, 83, 73, 115, 73, 110, 74, 108, 89, 50, 86, 112, 100, 109, 86, 107, 84, 87, 86, 122, 99, 50, 70, 110, 90, 88, 77, 105, 79, 110, 116, 57, 76, 67, 74, 120, 100, 87, 86, 49, 90, 83, 73, 54, 87, 49, 48, 115, 73, 110, 74, 118, 100, 87, 53, 107, 84, 110, 86, 116, 89, 109, 86, 121, 73, 106, 111, 120, 76, 67, 74, 121, 98, 51, 86, 117, 90, 67, 73, 54, 73, 109, 86, 53, 83, 109, 108, 90, 87, 69, 53, 115, 83, 87, 112, 118, 97, 86, 112, 89, 98, 69, 116, 108, 98, 72, 66, 89, 90, 85, 99, 120, 86, 70, 90, 87, 82, 110, 66, 85, 77, 110, 66, 71, 89, 122, 66, 115, 100, 86, 70, 116, 97, 71, 112, 105, 98, 69, 112, 76, 86, 87, 116, 111, 84, 109, 70, 86, 79, 88, 78, 106, 77, 50, 104, 78, 85, 107, 86, 119, 97, 49, 112, 115, 82, 84, 108, 81, 85, 48, 108, 122, 83, 87, 48, 120, 98, 71, 77, 122, 84, 109, 104, 97, 77, 108, 90, 54, 83, 87, 112, 118, 97, 86, 108, 86, 90, 70, 100, 106, 77, 107, 112, 73, 84, 48, 81, 119, 97, 85, 120, 68, 83, 110, 100, 90, 87, 69, 111, 119, 89, 86, 100, 87, 101, 107, 108, 113, 99, 68, 100, 74, 97, 107, 86, 112, 84, 50, 53, 122, 97, 87, 78, 73, 86, 109, 108, 105, 82, 50, 120, 113, 83, 87, 112, 118, 97, 86, 70, 86, 90, 70, 66, 87, 97, 51, 104, 71, 89, 86, 100, 83, 77, 109, 82, 72, 90, 70, 104, 107, 86, 108, 74, 112, 85, 87, 116, 87, 86, 108, 85, 120, 82, 88, 108, 90, 77, 85, 74, 76, 86, 106, 70, 71, 100, 48, 49, 84, 100, 68, 66, 83, 87, 69, 112, 70, 86, 70, 86, 115, 85, 69, 49, 72, 85, 110, 108, 83, 86, 51, 65, 48, 86, 86, 81, 119, 97, 85, 120, 68, 83, 109, 116, 104, 85, 48, 107, 50, 83, 87, 116, 79, 81, 49, 86, 86, 86, 84, 70, 108, 82, 107, 74, 85, 87, 109, 120, 79, 85, 109, 77, 121, 99, 69, 53, 108, 97, 48, 111, 49, 86, 68, 70, 83, 101, 86, 90, 71, 83, 109, 49, 84, 77, 71, 82, 70, 84, 48, 82, 79, 82, 70, 85, 121, 82, 108, 104, 105, 98, 71, 120, 53, 86, 87, 53, 71, 97, 49, 112, 69, 86, 108, 70, 97, 101, 107, 69, 53, 83, 87, 108, 51, 97, 86, 112, 88, 97, 50, 108, 80, 97, 85, 112, 117, 89, 106, 70, 87, 77, 107, 57, 72, 98, 68, 66, 90, 86, 50, 104, 50, 89, 87, 48, 49, 77, 69, 49, 88, 101, 69, 86, 78, 97, 51, 82, 73, 89, 86, 104, 75, 100, 87, 73, 119, 97, 70, 86, 84, 82, 71, 82, 89, 89, 109, 120, 119, 89, 86, 85, 119, 84, 107, 49, 108, 97, 122, 70, 52, 86, 84, 70, 83, 77, 109, 69, 119, 90, 69, 90, 81, 85, 48, 108, 122, 83, 87, 53, 75, 99, 69, 108, 113, 98, 50, 108, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 85, 77, 71, 108, 77, 81, 48, 112, 51, 89, 86, 78, 74, 78, 107, 108, 114, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 70, 79, 85, 108, 112, 100, 50, 108, 108, 98, 87, 116, 112, 84, 50, 108, 75, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 70, 78, 75, 79, 85, 120, 68, 83, 88, 108, 74, 97, 110, 65, 51, 83, 87, 53, 67, 77, 86, 108, 116, 101, 72, 66, 90, 101, 85, 107, 50, 83, 87, 116, 119, 98, 109, 70, 114, 79, 87, 49, 87, 85, 122, 108, 118, 90, 85, 86, 115, 85, 108, 77, 120, 86, 109, 104, 87, 86, 50, 116, 53, 89, 109, 49, 52, 77, 87, 74, 87, 89, 51, 74, 85, 98, 85, 90, 120, 89, 109, 49, 79, 78, 87, 82, 70, 83, 84, 86, 78, 98, 108, 74, 117, 84, 109, 49, 52, 100, 108, 108, 113, 87, 110, 78, 104, 82, 122, 103, 53, 83, 87, 108, 51, 97, 86, 112, 72, 97, 50, 108, 80, 97, 85, 112, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 81, 85, 48, 108, 122, 83, 87, 49, 87, 99, 69, 108, 113, 98, 50, 108, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 85, 77, 71, 108, 77, 81, 48, 112, 53, 89, 86, 78, 74, 78, 107, 108, 114, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 70, 79, 85, 108, 112, 100, 50, 108, 106, 82, 50, 116, 112, 84, 50, 108, 75, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 70, 78, 74, 99, 48, 108, 117, 99, 72, 66, 74, 97, 109, 57, 112, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 68, 66, 112, 90, 108, 103, 119, 99, 48, 108, 116, 90, 72, 108, 105, 77, 49, 90, 51, 87, 68, 74, 48, 98, 71, 86, 84, 83, 84, 90, 74, 97, 50, 120, 121, 90, 69, 86, 48, 97, 85, 49, 69, 86, 107, 49, 86, 77, 86, 89, 48, 84, 108, 90, 87, 83, 70, 78, 116, 99, 71, 108, 105, 98, 72, 66, 87, 86, 109, 48, 119, 78, 86, 74, 87, 82, 108, 100, 97, 82, 109, 82, 112, 85, 108, 82, 115, 82, 49, 89, 120, 86, 109, 57, 107, 86, 109, 120, 88, 85, 109, 116, 83, 85, 109, 74, 72, 97, 70, 90, 87, 77, 70, 112, 51, 86, 87, 49, 83, 99, 50, 74, 69, 84, 108, 82, 83, 82, 49, 74, 120, 86, 70, 100, 52, 82, 107, 57, 86, 98, 71, 53, 81, 86, 68, 66, 112, 84, 69, 78, 75, 101, 108, 112, 88, 84, 110, 108, 97, 87, 70, 74, 109, 89, 84, 74, 87, 78, 86, 103, 122, 84, 109, 57, 90, 87, 69, 112, 115, 83, 87, 112, 118, 97, 85, 49, 70, 77, 87, 70, 90, 86, 84, 107, 122, 89, 50, 116, 107, 85, 87, 78, 117, 97, 51, 104, 82, 87, 69, 111, 50, 89, 50, 115, 53, 87, 108, 100, 117, 99, 70, 108, 82, 86, 48, 90, 76, 87, 87, 49, 111, 77, 86, 90, 117, 84, 109, 57, 79, 86, 87, 120, 54, 86, 86, 100, 78, 77, 108, 77, 120, 82, 106, 86, 85, 97, 50, 119, 122, 87, 110, 111, 119, 97, 85, 120, 68, 83, 109, 120, 89, 77, 48, 53, 113, 87, 86, 100, 52, 97, 71, 78, 112, 83, 84, 90, 74, 98, 86, 85, 121, 86, 108, 82, 79, 86, 86, 70, 88, 98, 51, 108, 88, 98, 70, 112, 113, 89, 48, 85, 119, 101, 109, 70, 88, 83, 106, 90, 108, 82, 122, 86, 72, 86, 107, 104, 82, 77, 48, 49, 69, 90, 69, 116, 78, 77, 71, 120, 79, 89, 87, 49, 48, 83, 71, 86, 70, 77, 86, 104, 78, 86, 85, 112, 114, 85, 108, 82, 67, 85, 108, 111, 121, 99, 122, 108, 74, 97, 88, 100, 112, 87, 107, 89, 53, 101, 108, 107, 121, 82, 110, 78, 90, 87, 69, 108, 112, 84, 50, 108, 75, 99, 70, 82, 72, 86, 108, 90, 106, 86, 85, 112, 81, 87, 109, 116, 114, 77, 50, 73, 121, 78, 88, 90, 76, 77, 49, 69, 121, 89, 86, 90, 107, 83, 108, 86, 117, 84, 108, 86, 97, 77, 86, 90, 115, 86, 108, 90, 78, 77, 50, 77, 119, 78, 68, 82, 88, 87, 70, 74, 75, 84, 107, 104, 75, 87, 87, 78, 72, 83, 109, 112, 78, 83, 71, 82, 67, 85, 70, 78, 74, 99, 48, 108, 116, 84, 109, 90, 106, 77, 107, 53, 111, 89, 107, 100, 71, 101, 85, 108, 113, 98, 50, 108, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 85, 77, 71, 108, 77, 81, 48, 112, 53, 87, 68, 78, 79, 97, 108, 108, 88, 101, 71, 104, 106, 97, 85, 107, 50, 83, 87, 116, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 90, 67, 85, 86, 86, 71, 81, 108, 70, 86, 82, 107, 74, 82, 86, 85, 85, 53, 83, 87, 52, 119, 80, 83, 74, 57, 34, 44, 34, 111, 117, 116, 112, 117, 116, 34, 58, 34, 101, 121, 74, 84, 97, 87, 100, 117, 89, 88, 82, 49, 99, 109, 85, 105, 79, 109, 53, 49, 98, 71, 120, 57, 34, 44, 34, 103, 114, 111, 117, 112, 75, 101, 121, 34, 58, 34, 73, 107, 116, 75, 98, 48, 53, 76, 83, 85, 120, 53, 85, 71, 74, 106, 98, 110, 90, 85, 86, 109, 57, 69, 81, 86, 100, 87, 98, 69, 57, 70, 87, 85, 104, 117, 89, 86, 70, 68, 81, 108, 104, 85, 87, 70, 112, 82, 100, 108, 108, 51, 83, 68, 100, 106, 77, 108, 69, 57, 73, 103, 61, 61, 34, 44, 34, 109, 101, 115, 115, 97, 103, 101, 49, 34, 58, 91, 34, 65, 119, 65, 66, 65, 65, 65, 73, 70, 65, 84, 110, 69, 57, 74, 57, 74, 67, 121, 77, 122, 77, 72, 73, 53, 79, 116, 78, 70, 56, 111, 89, 80, 122, 99, 74, 74, 112, 97, 100, 105, 116, 71, 112, 49, 51, 107, 43, 68, 89, 75, 70, 76, 47, 73, 114, 87, 111, 97, 73, 53, 55, 100, 90, 81, 57, 105, 104, 111, 113, 53, 54, 66, 48, 120, 43, 49, 112, 50, 87, 85, 103, 105, 56, 122, 75, 107, 107, 55, 53, 66, 104, 34, 93, 125}
	data1 := arr2bytes(outdata1)
	ymsg := "AQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATswkEqaZHSd0NsYXpTXLnUG7UYA5LUUOYL3SsQK14HAAFQXtVwBE8obkzGw9VR/TM1T8gS62JI7pdofNeDxIjDFVpJ1b5KMWu56SwadFCxv5Vf4OvVQd+2gJsja6duozop"

	fmt.Println("len round0: ", len(data1))
	r, err := MPCPartSignRound1(0, data1, ymsg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(r)
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

	//dpkTest()

	mpc_cs_test()
	sigtest()

	//dkg_cs_test()

	//mpc_cs_test()
}

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
