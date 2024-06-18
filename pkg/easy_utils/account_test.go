package easy_utils

import (
	"encoding/json"
	"fmt"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"log"
	"testing"
	"time"
)

func TestPx(t *testing.T) {
	// 生成tron錢包
	accent, s := GenerateAccent() // 助记符 密钥
	fmt.Println(accent, s)

	// 将十六进制字符串解码为 btcec 私钥
	key, err := DecodePrivateKey(s)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(key)

	// 将公钥转换为 Tron 地址
	s2 := address.HexToAddress(fmt.Sprintf("%x", key.PubKey().SerializeCompressed())).Hex()
	fmt.Println(s2)

	// 将公钥转换为 Tron 地址
	addr, err := PublicKeyToTronAddress(key.PubKey())
	if err != nil {
		t.Error(err)
	}

	fmt.Println(address.PubkeyToAddress(*key.PubKey().ToECDSA()).String())

	fmt.Println(addr)
	fmt.Println(IsTrc20Address(addr))
}

func TestSendTRXToAddress(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	// 獲取tron balance
	balance, err := sdk.Balance("TU3qaiaP8DGCQJZWRdQLcUo6osRpYVQiVo")
	if err != nil {
		panic(err)
	}
	fmt.Println(balance)

	token1 := "4e4770272e2a743c6c37f60cac0bb0a3cc6ff85311ba8d4944028a4816a3d2f1"
	address2 := "TSW2S2g7JWS2FAobkpfEMBTRLZMEJddtRD"

	toAddress, err := sdk.SendTRXToAddress(token1, address2, 0.01, 0)
	if err != nil {
		fmt.Println(sdk.TransactionHash(toAddress))
		panic(err)
	}

	fmt.Println(sdk.TransactionHash(toAddress))

	indent, err := json.MarshalIndent(toAddress, "", " ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(indent))
}

func TestTRC20Balance(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	// 賬戶地址， 合約地址
	balance, err := sdk.TRC20Balance("TGrC1cgn7AY6AydZB69VhK8TJMdiYMhAJT", "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj")
	if err != nil {
		panic(err)
	}
	fmt.Println(balance)
}

func TestSendTRC20(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	token1 := "4e4770272e2a743c6c37f60cac0bb0a3cc6ff85311ba8d4944028a4816a3d2f1"
	address2 := "TSW2S2g7JWS2FAobkpfEMBTRLZMEJddtRD"
	contract := "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj" // 測試網絡usdt 地址

	toAddress, err := sdk.SendTRC20ToAddress(token1, address2, contract, 1, 4)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(sdk.TransactionHash(toAddress))

	balance, err := sdk.TRC20Balance(address2, contract)
	if err != nil {
		panic(err)
	}
	fmt.Println(balance)
}

// 獲取trc20代幣轉賬記錄
func TestTRC20TransactionHistory(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	// 賬戶地址， 合約地址
	balance, err := sdk.TRC20TransactionHistory("TSW2S2g7JWS2FAobkpfEMBTRLZMEJddtRD", "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj", 10, true, false)
	if err != nil {
		panic(err)
	}
	fmt.Println(balance)
}

// 獲取trc20代幣轉賬記錄
func TestTRC20Node(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	// 賬戶地址， 合約地址
	outChannel := make(chan TxNode, 10)

	go func() {
		for {
			token1 := "4e4770272e2a743c6c37f60cac0bb0a3cc6ff85311ba8d4944028a4816a3d2f1"
			address2 := "TSW2S2g7JWS2FAobkpfEMBTRLZMEJddtRD"
			contract := "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj" // 測試網絡usdt 地址

			toAddress, err := sdk.SendTRC20ToAddress(token1, address2, contract, 0.02, 4)
			if err != nil {
				log.Fatalln(err)
			}

			fmt.Println(sdk.TransactionHash(toAddress))
			time.Sleep(time.Second)
		}
	}()

	go func() {
		for {
			select {
			case data := <-outChannel:
				data.Print()
			}
		}
	}()

	sdk.TRC20Tx("", outChannel)
}

func TestParseTRC20(t *testing.T) {
	sdk, err := NewEasyUtilsSDK("grpc.nile.trongrid.io", "https://nile.trongrid.io", "271c5ed4-9a99-48c2-8522-bceccb441927", false, 0)
	if err != nil {
		panic(err)
	}

	tx, err := sdk.GetTransactionByID("68fed6a9baa5736fff0f2a10c915d3844bd33b7dfc39af99231a59e70d73ec6f")
	if err != nil {
		panic(err)
	}

	contract := "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj" // 測試網絡usdt 地址

	trc20, err := sdk.ParseTRC20(tx, contract)
	if err != nil {
		panic(err)
	}
	trc20.Print()
}
