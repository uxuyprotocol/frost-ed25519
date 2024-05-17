package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/taurusgroup/frost-ed25519/ed25519"
	"github.com/taurusgroup/frost-ed25519/solana"

	"io/ioutil"
	"log"
	"net/http"
)

type PrevParty int

const (
	ClientParty PrevParty = iota + 1
	ServerParty
)

type Slice struct {
	Round      int    `json:"round"`
	Message1   string `json:"message1,omitempty"`
	Message2   string `json:"message2,omitempty"`
	OutputData []byte `json:"output_data,omitempty"`
	SessionId  string `json:"session_id"`
	Slice      string `json:"slice,omitempty"`
}

type MpcSign struct {
	Round      int    `json:"round"`
	SignMsg    string `json:"sign_msg,omitempty"`
	Message1   string `json:"message1,omitempty"`
	Message2   string `json:"message2,omitempty"`
	SliceKey   string `json:"slice_key,omitempty"`
	OutputData []byte `json:"output_data,omitempty"`
	SessionId  string `json:"session_id"`
	TransID    string `json:"trans_id,omitempty"`
}

type SolTrans struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Amount  uint64 `json:"amount"`
	IsDev   bool   `json:"is_dev"`
	TransID string `json:"trans_id"`
	Sig     string `json:"sig"`
}

var dkgPool []Slice

var signPool []MpcSign

var solTransPool []SolTrans

var serverSlice = Slice{
	SessionId: "server001",

	Slice: "ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAibTFyaUNtUkZGTFpKMFlWbHN0bTE2RjJXWFg3QUxUZXpYY3VCWHl1N1Z3TT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJuZzgwaWVCRC9JNnJKdjJ5TmR6QUpIRVpzM3p5RHNmTDFnVUFtbHJLbEY0PSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAibG1YeE4rWjBJZy9NYlhRUUN3VGJ5YktjUUNjN0RuVERybVVPLzNLTFVpUT0iLAogICAiMiI6ICJqTXUwVGd1RzNWd1JiTHVwTkZMeGp2cG9Pank2bklCZy90K2FyOUJ0VndjPSIKICB9CiB9Cn0=",
}

var serverMpc = MpcSign{
	SessionId: "server001",
	SliceKey:  "ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAibTFyaUNtUkZGTFpKMFlWbHN0bTE2RjJXWFg3QUxUZXpYY3VCWHl1N1Z3TT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJuZzgwaWVCRC9JNnJKdjJ5TmR6QUpIRVpzM3p5RHNmTDFnVUFtbHJLbEY0PSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAibG1YeE4rWjBJZy9NYlhRUUN3VGJ5YktjUUNjN0RuVERybVVPLzNLTFVpUT0iLAogICAiMiI6ICJqTXUwVGd1RzNWd1JiTHVwTkZMeGp2cG9Pank2bklCZy90K2FyOUJ0VndjPSIKICB9CiB9Cn0=",
}

func handleDkgClientRound(round int, message string) (string, error) {
	switch round {
	case 0:
		out, err := ed25519.SliceKeyGenRound0(2, 1)
		if err != nil {
			return "", err
		}
		msg1, err := ed25519.GetMessageFromKeygenOutData(out, 0)
		serverSlice.OutputData = out
		serverSlice.Message1 = msg1
		return msg1, nil
	case 1:
		out, err := ed25519.SliceKeyGenRound1(1, serverSlice.OutputData, message)
		if err != nil {
			return "", err
		}
		msg2, err := ed25519.GetMessageFromKeygenOutData(out, 1)
		serverSlice.OutputData = out
		serverSlice.Message2 = msg2
		return msg2, nil
	case 2:
		out, err := ed25519.SliceKeyGenRound2(1, serverSlice.OutputData, message)
		if err != nil {
			return "", err
		}
		serverSlice.OutputData = out
		return "", nil
	case 3:
		slice, err := ed25519.DKGSlice(2, serverSlice.OutputData)
		if err != nil {
			return "", err
		}
		serverSlice.Slice = slice
		serverMpc.SliceKey = slice
		return slice, nil
	}
	return "", fmt.Errorf("round %d not found", round)
}

func handleSignClientRound(round int, yMsg string, message string) (string, error) {

	var unsignmessage = message

	switch round {
	case 0:
		out, err := ed25519.MPCPartSignRound0(2, 1, serverSlice.Slice, unsignmessage)
		if err != nil {
			return "", err
		}
		msg1, err := ed25519.GetMessageFromSignOutData(out, 0)
		serverMpc.OutputData = out
		serverMpc.Message1 = msg1
		fmt.Println("round--------end")
		fmt.Println("round0 msg: ", msg1)

		return msg1, nil
	case 1:
		out, err := ed25519.MPCPartSignRound1(1, serverMpc.OutputData, yMsg)
		if err != nil {
			return "", err
		}
		msg2, err := ed25519.GetMessageFromSignOutData(out, 1)
		serverMpc.OutputData = out
		serverMpc.Message2 = msg2
		return msg2, nil
	case 2:
		sig, err := ed25519.MPCPartSignRound2(1, serverMpc.OutputData, yMsg, unsignmessage)
		if err != nil {
			return "", err
		}
		gk, err := ed25519.GetGroupkeyFromSlice(serverMpc.SliceKey)
		if err != nil {
			return "", err
		}
		ver := ed25519.VerifySignature(gk, message, sig)
		fmt.Println("签名结果验证: ", sig, ver)
		return sig, nil
	}
	return "", fmt.Errorf("round %d not found", round)
}

func mpcHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var sliceFromClient Slice
	err = json.Unmarshal(body, &sliceFromClient)
	if err != nil {
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	found := false
	for i, d := range dkgPool {
		if d.SessionId == sliceFromClient.SessionId {
			// Update the Slice in dkgPool
			dkgPool[i] = sliceFromClient
			found = true
			break
		}
	}

	if !found {
		// Append sliceFromClient to dkgPool
		dkgPool = append(dkgPool, sliceFromClient)
	}

	if sliceFromClient.SessionId == "" {
		http.Error(w, "Invalid Slice Context", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(sliceFromClient)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch sliceFromClient.Round {
	case 0:
		_, er := handleDkgClientRound(sliceFromClient.Round, sliceFromClient.Message1)
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		jsonstr := fmt.Sprintf(`{"round": %d, "message": "%s"}`, 0, serverSlice.Message1)
		data, err := json.Marshal(jsonstr)
		if err != nil {
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	case 1:
		_, er := handleDkgClientRound(sliceFromClient.Round, sliceFromClient.Message2)
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		jsonstr := fmt.Sprintf(`{"round": %d, "message": "%s"}`, 1, serverSlice.Message2)
		data, err := json.Marshal(jsonstr)
		if err != nil {
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	case 2:
		_, er := handleDkgClientRound(sliceFromClient.Round, sliceFromClient.Message2)
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		slice, err := handleDkgClientRound(3, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		gk, err := ed25519.GetGroupkeyFromSlice(slice)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		address := solana.GetSolAddress(gk)

		fmt.Println("dkg server slice: ", slice)
		jsonstr := fmt.Sprintf(`{"message":"success", "sol_address": "%v"}`, 2, address)
		fmt.Println(jsonstr)

		data, err := json.Marshal(jsonstr)
		if err != nil {
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	}

	//w.Write(response)
	fmt.Println(response)
	http.Error(w, fmt.Sprintf("round number invalid [%d]", sliceFromClient.Round), http.StatusInternalServerError)
}

// mpcSignHandler 生成交易签名
func mpcSignHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var signFromClient MpcSign
	err = json.Unmarshal(body, &signFromClient)
	if err != nil {
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	fmt.Println("request----------------------------------")
	fmt.Println(string(body), err)

	found := false
	for i, d := range signPool {
		if d.SessionId == signFromClient.SessionId {
			// Update the Slice in dkgPool
			signPool[i] = signFromClient
			found = true
			break
		}
	}

	if !found {
		// Append sliceFromClient to dkgPool
		signPool = append(signPool, signFromClient)
	}

	if signFromClient.SessionId == "" {
		http.Error(w, "Invalid Slice Context", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(signFromClient)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch signFromClient.Round {
	case 0:

		_, er := handleSignClientRound(signFromClient.Round, "", signFromClient.SignMsg)
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		jsonstr := fmt.Sprintf(`{"round": %d, "message": "%s"}`, 0, serverMpc.Message1)
		data, err := json.Marshal(jsonstr)
		if err != nil {
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		fmt.Println("-------response--------------")
		fmt.Println(jsonstr)
		w.Write(data)
		return
	case 1:
		_, er := handleSignClientRound(signFromClient.Round, signFromClient.Message1, serverMpc.SignMsg)
		if er != nil {
			fmt.Println(er)
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		jsonstr := fmt.Sprintf(`{"round": %d, "message": "%s"}`, 1, serverMpc.Message2)
		data, err := json.Marshal(jsonstr)
		if err != nil {
			fmt.Println(er)
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	case 2:

		if signFromClient.TransID == "" {
			http.Error(w, "trans_id must not be null", http.StatusBadRequest)
			return
		}
		var trans *SolTrans
		var index int
		for i, sol := range solTransPool {
			if sol.TransID == signFromClient.TransID {
				trans = &sol
				index = i
				break
			}
		}
		if trans == nil {
			http.Error(w, "Can't found this trans", http.StatusBadRequest)
		}

		sig, er := handleSignClientRound(signFromClient.Round, signFromClient.Message2, signFromClient.SignMsg)
		if er != nil {
			fmt.Println(er)
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return
		}
		trans.Sig = sig

		fmt.Println("set sig: ", trans.Sig)
		solTransPool[index] = *trans

		jsonstr := fmt.Sprintf(`{"round": %d, "trans": "%s"}`, 2, signFromClient.TransID)

		data, err := json.Marshal(jsonstr)
		if err != nil {
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	}

	//w.Write(response)
	fmt.Println(response)
	http.Error(w, fmt.Sprintf("round number invalid [%d]", signFromClient.Round), http.StatusInternalServerError)
}

// initSolTransHandler 初始化 solana 交易，生成交易 msg
func initSolTransHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)

	fmt.Println("------initSolTransHandler--------")
	fmt.Println(string(body), err)

	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var input SolTrans
	err = json.Unmarshal(body, &input)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	from, err := base64.StdEncoding.DecodeString(input.From)
	to, err := base64.StdEncoding.DecodeString(input.To)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}
	transMsg, err := solana.InitSolTransaction(from, to, input.Amount, input.IsDev)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error initializing transaction", http.StatusInternalServerError)
		return
	}
	//生成交易ID
	transId, err := uuid.GenerateUUID()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error generating UUID", http.StatusInternalServerError)
		return
	}

	// 添加到 transPool
	input.TransID = transId
	solTransPool = append(solTransPool, input)

	fmt.Println("add to transpool", input)

	type response struct {
		TransID  string `json:"trans_id"`
		TransMsg string `json:"trans_message"`
	}

	jsonstr := response{transId, transMsg}
	fmt.Println("-------initsol response -----------")
	fmt.Println(jsonstr)

	data, err := json.Marshal(jsonstr)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Write(data)
	return
}

// 完成 Solana 交易
func submitSolTransHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)

	fmt.Println("------submitSolTransHandler--------")
	fmt.Println(string(body), err)

	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	type Input struct {
		TransID string `json:"trans_id"`
	}

	var input Input
	err = json.Unmarshal(body, &input)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	var trans *SolTrans
	for _, sol := range solTransPool {
		if sol.TransID == input.TransID {
			trans = &sol
			break
		}
	}

	if trans == nil {
		http.Error(w, "No trans record found! ", http.StatusBadRequest)
		return
	}

	from, err := base64.StdEncoding.DecodeString(trans.From)
	to, err := base64.StdEncoding.DecodeString(trans.To)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	fmt.Println("submitSolTrans params--------------")
	fmt.Printf("[%v,%v,%v,%v,%v]\n", trans.Sig, from, to, trans.Amount, trans.IsDev)

	transHash, err := solana.SubmitSolTransaction(trans.Sig, from, to, trans.Amount, trans.IsDev)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error submitting transaction", http.StatusInternalServerError)
		return
	}

	type response struct {
		TransHash string `json:"trans_hash"`
		Message   string `json:"message"`
	}

	res := response{
		transHash,
		"success",
	}

	data, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}
	w.Write(data)
	return
}

func poolsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	response, err := json.Marshal(dkgPool)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
func testMockServer() {
	//dkgPool := []Slice{}
	//mpcContext := Slice{
	//
	//	//Ctx:    "initial",
	//	//Round:  0,
	//}
	//
	//dkgPool = append(dkgPool, mpcContext)

	http.HandleFunc("/slice", mpcHandler)
	http.HandleFunc("/mpc_sign", mpcSignHandler)
	http.HandleFunc("/pools", poolsHandler)
	http.HandleFunc("/init_sol_transaction", initSolTransHandler)
	http.HandleFunc("/sublmit_sol_transaction", submitSolTransHandler)

	fmt.Println("Starting server on port 8000")
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	testMockServer()
}

/**
curl -X POST -H "Content-Type: application/json" -d '{"round":0, "message1":"789djkshkdj", "session_id":"shjakhdsakdsa"}' http://10.152.30.148:8000/slice

*/
