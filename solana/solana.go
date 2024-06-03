package solana

//package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/blocto/solana-go-sdk/client"
	sdkRpc "github.com/blocto/solana-go-sdk/rpc"
	"github.com/davecgh/go-spew/spew"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/gagliardetto/solana-go/rpc/ws"
)

var transactionPool []*solana.Transaction

func GetSolanaBalance(pubkey string) {

	c := client.NewClient(rpc.DevNet_RPC)

	accountB, _ := base64.StdEncoding.DecodeString(pubkey)
	account := solana.PublicKeyFromBytes(accountB)

	fmt.Printf("solana address: %v\n", account.String())
	// get balance
	balance, err := c.GetBalance(
		context.TODO(),
		account.String(),
	)
	if err != nil {
		fmt.Printf("failed to get balance, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// get balance with sepcific commitment
	balance, err = c.GetBalanceWithConfig(
		context.TODO(),
		account.String(),
		client.GetBalanceConfig{
			Commitment: sdkRpc.CommitmentProcessed,
		},
	)

	if err != nil {
		fmt.Printf("failed to get balance with cfg, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// for advanced usage. fetch full rpc response
	res, err := c.RpcClient.GetBalance(
		context.TODO(),
		account.String(),
	)
	if err != nil {
		fmt.Printf("failed to get balance via rpc client, err: %v", err)
	}
	fmt.Printf("response: %+v\n", res.Result.Value)
}

func solTransTestv2() {

	keys := "ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAicThZQXdmd1g1QWxrOGx1Vm5wdHk2L2djQzRZYVc1bVpvQTRSdU4ybVZBMD0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiR1AxUzJ3Wmx6NGlpamhhUVBFV2hxMWhUNVF3U1RXeExVWHozN0ZFU1FnYz0iCiAgfQogfQp9,ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAicEc0Vk00cTg2SVFFQ1FJS09uMG5mQzBIQXhIL0lCV1hkeGsrZXBNUHJnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJ4SzNhVE8xS0JXYXJMWTVRbHhFUFV4R2xneXlRWTdvUFI0YVFKTThDL0NvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiWEdiYlF5Nlh1SjNvdU1XL2tjZmFZT3lRYUNyWVNPYUdNaHRhNDBjSlZ5bz0iCiAgfQogfQp9"
	//
	//from1 := "GzIZ/Uxza5+dMwqIiUBK5JbfBfKoHZxYXSfgXgKgVfo="
	//to1 := "g890V/MLnTTTsKXF2Abd8xvSLzaXtrO4H4RvzhxK7iU="
	//buildSolanaTransactionMsgV1(from1, to1, 333, keys, false)
	//
	////groupkey
	//from2 := "xK3aTO1KBWarLY5QlxEPUxGlgyyQY7oPR4aQJM8C/Co="
	//to2 := "QtXA0VMuarDYLFz7JlrcUqfVKRgxI2iXzicN9jqqixA="
	//buildSolanaTransactionMsgV1(from2, to2, 333, keys, true)

	from3 := "GzIZ/Uxza5+dMwqIiUBK5JbfBfKoHZxYXSfgXgKgVfo="
	to3 := "g890V/MLnTTTsKXF2Abd8xvSLzaXtrO4H4RvzhxK7iU="

	fmt.Printf("%v,%v,%v\n\n", keys, from3, to3)
	//solanaFaucet(from3, 1^9)
	//solanaFaucet(to3, 1^9)
	GetSolanaBalance(from3)
	GetSolanaBalance(to3)
	//buildSolanaTransactionMsgV1(from3, to3, 1, keys, true)
	//
	//from4 := "xK3aTO1KBWarLY5QlxEPUxGlgyyQY7oPR4aQJM8C/Co="
	//to4 := "QtXA0VMuarDYLFz7JlrcUqfVKRgxI2iXzicN9jqqixA="
	//buildSolanaTransactionMsgV1(from4, to4, 333, keys, false)

	//from5 := "GP1S2wZlz4iijhaQPEWhq1hT5QwSTWxLUXz37FESQgc="
	//to5 := "XgqVOXSBimes357Xn6XIwljwy4hVXkCx2oEG4qcbvA0="
	//buildSolanaTransactionMsgV1(from5, to5, 333, keys, false)

}

// GetSolAddress 生成 Solana 地址
func GetSolAddress(publicKey []byte) string {
	account := solana.PublicKeyFromBytes(publicKey)

	return account.String()
}

// InitSolTransaction 初始化一笔 Sol 交易
func InitSolTransaction(from []byte, to []byte, amount uint64, isDev bool) (string, string, error) {

	var rpcClient *rpc.Client
	if isDev {
		rpcClient = rpc.New(rpc.DevNet_RPC)
	} else {
		rpcClient = rpc.New(rpc.MainNetBeta_RPC)
	}

	fromAccount := solana.PublicKeyFromBytes(from)

	toAccount := solana.PublicKeyFromBytes(to)

	fmt.Printf("initSolTrans:  [%v, %v,%v,%v]\n", fromAccount.String(), toAccount.String(), amount, isDev)

	recent, err := rpcClient.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return "", "", err
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(
				amount,
				fromAccount,
				toAccount,
			).Build(),
		},
		recent.Value.Blockhash,
		solana.TransactionPayer(fromAccount),
	)

	if err != nil {
		return "", "", err
	}

	//return tx.ToBase64(), nil
	messageBytes, err := tx.Message.MarshalBinary()
	msg64 := tx.Message.ToBase64()

	if err != nil {
		return "", "", err
	}

	msg641 := base64.StdEncoding.EncodeToString(messageBytes)
	fmt.Println("待签名消息1: ", string(messageBytes))
	fmt.Println("待签名消息2: ", msg64)
	fmt.Println("待签名消息3: ", msg641)

	//return msg64, nil

	////TODO: 此处需要考虑并发 用 uuid 标识
	//transactionPool = append(transactionPool, tx)
	//return string(messageBytes), nil
	txHash := tx.MustToBase64()

	return msg641, txHash, nil
}

// SubmitSolTransaction 根据签名完成一笔交易
func SubmitSolTransaction(sig string, txHash string, isDev bool) (string, error) {
	// 将签名解码为字节片
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return "", err
	}

	signature := solana.SignatureFromBytes(sigBytes)

	//tx := transactionPool[0]
	tx := solana.Transaction{}
	err = tx.UnmarshalBase64(txHash)

	var rpcClient *rpc.Client
	if isDev {
		rpcClient = rpc.New(rpc.DevNet_RPC)
	} else {
		rpcClient = rpc.New(rpc.MainNetBeta_RPC)
	}
	//
	//fromAccount := solana.PublicKeyFromBytes(from)
	//toAccount := solana.PublicKeyFromBytes(to)
	//
	//fmt.Printf("sig:%v, from: %v, to: %v, amt: %v, isDev: %v\n", sigBytes, fromAccount.String(), toAccount.String(), amount, isDev)
	//
	//recent, err := rpcClient.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
	//if err != nil {
	//	return "", err
	//}
	//
	//tx, err := solana.NewTransaction(
	//	[]solana.Instruction{
	//		system.NewTransferInstruction(
	//			amount,
	//			fromAccount,
	//			toAccount,
	//		).Build(),
	//	},
	//	recent.Value.Blockhash,
	//	solana.TransactionPayer(fromAccount),
	//)
	//if err != nil {
	//	return "", err
	//}

	msg, err := tx.Message.MarshalBinary()
	fmt.Println("待签名消息3: ", string(msg))
	//添加签名
	tx.Signatures = append(tx.Signatures, signature)

	//签名校验
	err = tx.VerifySignatures() // 将签名追加到交易的签名字段中
	if err != nil {
		fmt.Println("签名校验失败.....")
		return "", err
	}

	var wsClient *ws.Client
	if isDev {
		wsClient, err = ws.Connect(context.Background(), rpc.DevNet_WS)
		if err != nil {
			return "", err
		}
	} else {
		wsClient, err = ws.Connect(context.Background(), rpc.MainNetBeta_WS)
		if err != nil {
			return "", err
		}
	}

	fsig, err := confirm.SendAndConfirmTransaction(
		context.Background(),
		rpcClient,
		wsClient,
		&tx,
	)
	if err != nil {
		return "", err
	}
	spew.Dump(sig)

	fmt.Println("transaction finish: ", fsig.String(), tx.Message.RecentBlockhash.String())
	return fsig.String(), nil
}

func main() {
	
}

/*
	type Secret struct {
		ID     int    `json:"id"`
		Secret string `json:"secret"`
	}

	type Shares struct {
		T        int               `json:"t"`
		GroupKey string            `json:"groupkey"`
		Shares   map[string]string `json:"shares"`
	}

	type CombinedOutput struct {
		Secrets map[string]Secret `json:"Secrets"`
		Shares  Shares            `json:"Shares"`
	}

	type FKeyGenOutput struct {
		Secrets map[party.ID]*eddsa.SecretShare
		Shares  *eddsa.Public
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

	func buildSolanaTransactionMsg(from string, to string, amount uint64) string {
		// Create a new RPC client:
		rpcClient := rpc.New(rpc.DevNet_RPC)

		accountFrom, err := solana.PublicKeyFromBase58(from)
		accountTo, err := solana.PublicKeyFromBase58(to)
		if err != nil {
			panic(err)
			return ""
		}

		recent, err := rpcClient.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
		if err != nil {
			panic(err)
		}

		tx, err := solana.NewTransaction(
			[]solana.Instruction{
				system.NewTransferInstruction(
					amount,
					accountFrom,
					accountTo,
				).Build(),
			},
			recent.Value.Blockhash,
			solana.TransactionPayer(accountFrom),
		)
		if err != nil {
			panic(err)
		}

		tx.Message.SetVersion(solana.MessageVersionV0)

		// 指定头部信息
		//tx.Message.Header = solana.MessageHeader{
		//	NumRequiredSignatures:       1, // 设置需要的签名数量
		//	NumReadonlySignedAccounts:   0, // 设置只读已签名账户数量
		//	NumReadonlyUnsignedAccounts: 0, // 设置只读未签名账户数量
		//}

		//tx.Message.SetVersion(solana.MessageVersionV0)

		messageBytes, err := tx.Message.MarshalBinary()
		messageJson, err := tx.Message.MarshalJSON()
		messageb64 := base64.StdEncoding.EncodeToString(messageBytes)

		message642, err := tx.ToBase64()

		if err != nil {
			log.Fatalf("serialize message error, err: %v", err)
		}

		fmt.Printf("Serialized Message for Signature: %x\n, %v\n", messageBytes, string(messageJson)) //msg := "交易信息"

		fmt.Printf("messageb64: [%v\n, %v\n]", messageb64, message642)

		//return string(messageBytes)

		mbb, _ := tx.Message.MarshalLegacy()
		return string(mbb)

		//return message642
	}

func solanaTransactionSignature(keys string, messageStr string, toEd25519 bool) string {

	// MPC 签名
	slices, err := decode2Bytes(keys)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	message := []byte(messageStr)

	if slices == nil {
		fmt.Println("verify failed slices is nil")
		return ""
	}

	mjson, err := mergeJson(slices)

	fmt.Println("msg: ", len(message))
	fmt.Println("merged: ", string(mjson))
	fmt.Println("error: ", err)

	var kgOutput FKeyGenOutput

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
	id1 := partyIDs[1]
	sig2 := outputs[id1].Signature
	if sig == nil {
		fmt.Println("null signature")
		return ""
	}

	fmt.Printf("GKED25519: [%v, %v]\n\n", base64.StdEncoding.EncodeToString(pk.ToEd25519()), pk.ToEd25519())

	fmt.Printf("ver111: pk:%v\n message: %v\n sig: %v\n\n", pk.ToEd25519(), message, sig)

	if !ed25519.Verify(pk.ToEd25519(), message, sig.ToEd25519()) {
		fmt.Println("signature verification failed (ed25519)")
		return ""
	}

	if !pk.Verify(message, sig) {
		fmt.Println("signature verification failed")
		return ""
	}

	fmt.Printf("Success: signature is\nr: %x\ns: %x\n", sig.R.Bytes(), sig.S.Bytes())
	fmt.Printf("Success: signatur2 is\nr: %x\ns: %x\n", sig2.R.Bytes(), sig2.S.Bytes())
	sigValue, err := sig.MarshalBinary()

	//return string(sigValue)

	sigb64 := base64.StdEncoding.EncodeToString(sigValue)
	fmt.Printf("Success: signature is\n%x\n", sigb64)

	pkjson, err := pk.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	fmt.Printf("pk: %s\n", string(pkjson))

	if toEd25519 {
		//return base64.StdEncoding.EncodeToString(sig.ToEd25519())

		sig1 := sig.ToEd25519()
		sig2 := []byte(string(sig.ToEd25519()))
		sig3 := base64.StdEncoding.EncodeToString(sig.ToEd25519())
		sig4, _ := base64.StdEncoding.DecodeString(sig3)
		fmt.Println(sig1, sig2, sig3, sig4)

		fmt.Printf("sig333: [%v, %v]\n\n", string(sig.ToEd25519()), []byte(string(sig.ToEd25519())))
		return string(sig.ToEd25519())
	}
	return sigb64

}

	func solanaSendTransaction(signature string, msgHash string) {
		// 创建交易
		rpcClient := rpc.New(rpc.DevNet_RPC)

		msg, err := types.MessageDeserialize([]byte(msgHash))

		if err != nil {
			fmt.Printf("partse msg fail: %v\n", err)
			return
		}

		tx := types.Transaction{
			Signatures: []types.Signature{
				[]byte(signature),
			},
			Message: msg,
		}

		//// 将交易编码
		rawTx, err := tx.Serialize()

		if err != nil {
			log.Fatalf("Failed to serialize transaction: %v", err)
		}

		transaction, err := types.TransactionDeserialize(rawTx)
		if err != nil {
			log.Fatalf("Failed to deserialize transaction: %v", err)
		}
		fmt.Println("transaction: ", transaction)

		// 输出序列化后的交易长度和内容，查看是否正常
		fmt.Printf("Serialized transaction length: %d, content: %x\n", len(rawTx), rawTx)
		txb64 := base64.StdEncoding.EncodeToString(rawTx)
		fmt.Printf("Transaction length: %d, b64content: %x\n", len(txb64), txb64)

		// 发送交易
		//txHash, err := rpcClient.SendEncodedTransaction(context.Background(), txb64)
		txHash, err := rpcClient.SendRawTransaction(context.Background(), rawTx)
		if err != nil {
			log.Fatalf("Failed to send transaction: %v", err)
		}

		fmt.Printf("Transaction has been sent with hash: %s\n", txHash)
	}

	func buildSolanaTransactionMsgV1(from string, to string, amount uint64, keys string, toEd25519 bool) {
		// Create a new RPC client:
		rpcClient := rpc.New(rpc.DevNet_RPC)

		fromB, err := base64.StdEncoding.DecodeString(from)
		toB, err := base64.StdEncoding.DecodeString(to)
		accountFrom := solana.PublicKeyFromBytes(fromB)
		accountTo := solana.PublicKeyFromBytes(toB)

		fmt.Printf("fromPubKey: %v", fromB)

		if err != nil {
			panic(err)
			return
		}

		recent, err := rpcClient.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
		if err != nil {
			panic(err)
		}

		tx, err := solana.NewTransaction(
			[]solana.Instruction{
				system.NewTransferInstruction(
					amount,
					accountFrom,
					accountTo,
				).Build(),
			},
			recent.Value.Blockhash,
			solana.TransactionPayer(accountFrom),
		)
		if err != nil {
			panic(err)
		}

		//tx.Message.SetVersion(solana.MessageVersionV0)

		// 指定头部信息
		//tx.Message.Header = solana.MessageHeader{
		//	NumRequiredSignatures:       1, // 设置需要的签名数量
		//	NumReadonlySignedAccounts:   0, // 设置只读已签名账户数量
		//	NumReadonlyUnsignedAccounts: 0, // 设置只读未签名账户数量
		//}

		//tx.Message.SetVersion(solana.MessageVersionV0)

		messageBytes, err := tx.Message.MarshalBinary()
		messageJson, err := tx.Message.MarshalJSON()
		messageb64 := base64.StdEncoding.EncodeToString(messageBytes)

		message642, err := tx.ToBase64()

		if err != nil {
			log.Fatalf("serialize message error, err: %v", err)
		}

		fmt.Printf("Serialized Message for Signature: %x\n, %v\n", messageBytes, string(messageJson)) //msg := "交易信息"

		fmt.Printf("messageb64: [%v\n, %v\n]", messageb64, message642)

		//return string(messageBytes)

		//mbb, _ := tx.Message.MarshalLegacy()

		sig := solanaTransactionSignature(keys, string(messageBytes), toEd25519)

		fmt.Printf("sig444: [%v, %v]\n\n", sig, []byte(sig))

		//bb1, _ := base64.StdEncoding.DecodeString(messageb64)
		//bb2, _ := base64.StdEncoding.DecodeString(message642)
		//sig := solanaTransactionSignature(keys, string(bb2), toEd25519)
		//sig := solanaTransactionSignature(keys, message642, toEd25519)

		// 将签名解码为字节片
		signature := solana.SignatureFromBytes([]byte(sig))
		if err != nil {
			log.Fatalf("Failed to decode signature: %v", err)
		}
		fmt.Printf("Signature: %x\n", signature)

		tx.Signatures = append(tx.Signatures, signature)

		isSigner1 := tx.IsSigner(accountFrom)
		isSigner2 := tx.IsSigner(accountTo)
		fmt.Printf("isSigner: [%v, %v]\n", isSigner1, isSigner2)

		//使用ed25519 签名校验
		fmt.Printf("ver222: pk:%v\n message: %v\n sig: %v\n\n", fromB, messageBytes, []byte(sig))
		fmt.Printf("sig555: [%v, %v]\n\n", sig, []byte(sig))
		edver := ed25519.Verify(fromB, messageBytes, []byte(sig))
		if !edver {
			panic("ed25519 signature verification failed")
		}

		//签名校验
		err = tx.VerifySignatures() // 将签名追加到交易的签名字段中
		if err != nil {
			log.Fatalf("Failed to verify signature: %v", err)
			return
		}

		//txb64, err := tx.ToBase64()

		if err != nil {
			fmt.Printf("Failed to serialize transaction: %v", err)
			return
		}

		wsClient, err := ws.Connect(context.Background(), rpc.DevNet_WS)
		if err != nil {
			panic(err)
		}
		fsig, err := confirm.SendAndConfirmTransaction(
			context.Background(),
			rpcClient,
			wsClient,
			tx,
		)
		if err != nil {
			fmt.Printf("Failed to send confirmation: %v", err)
		}
		spew.Dump(sig)

		fmt.Println(fsig)

}

	func solanaFaucet(pubkey string, amount uint64) {
		c := client.NewClient(rpc.DevNet_RPC)

		accountB, _ := base64.StdEncoding.DecodeString(pubkey)
		account := solana.PublicKeyFromBytes(accountB)

		fmt.Printf("solana address: %v\n", account.String())

		// request for 1 SOL airdrop using RequestAirdrop()
		txhash, err := c.RequestAirdrop(
			context.TODO(),   // request context
			account.String(), // wallet address requesting airdrop
			amount,           // amount of SOL in lamport
		)
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Printf("txhash: %s\n", txhash)

}
*/
