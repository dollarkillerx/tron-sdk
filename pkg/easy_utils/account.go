package easy_utils

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/client"
	"github.com/fbsobreira/gotron-sdk/pkg/common"
	"github.com/fbsobreira/gotron-sdk/pkg/common/decimals"
	"github.com/fbsobreira/gotron-sdk/pkg/keys"
	"github.com/fbsobreira/gotron-sdk/pkg/mnemonic"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/api"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/go-resty/resty/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// GenerateAccent generates a new accent
func GenerateAccent() (string, string) { // 助记符 密钥
	generate := mnemonic.Generate()
	private, _ := keys.FromMnemonicSeedAndPassphrase(generate, "", 0)
	return generate, ExportPrivateKeyAsHex(private)
}

// ExportPrivateKeyAsHex exports the private key as a hex string
func ExportPrivateKeyAsHex(privateKey *btcec.PrivateKey) string {
	return fmt.Sprintf("%x", privateKey.Serialize())
}

// DecodePrivateKey decodes a hex string to a btcec private key 将十六进制字符串解码为 btcec 私钥
func DecodePrivateKey(hexKey string) (*btcec.PrivateKey, error) {
	privKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return privKey, nil
}

// PublicKeyToTronAddress converts a public key to a Tron address PublicKeyToTronAddress 将公钥转换为 Tron 地址
func PublicKeyToTronAddress(pubKey *btcec.PublicKey) (string, error) {
	return address.PubkeyToAddress(*pubKey.ToECDSA()).String(), nil
}

func IsTrc20Address(address string) bool {
	_, err := common.DecodeCheck(address)
	return err == nil
}

type EasyUtilsSDK struct {
	conn            *client.GrpcClient
	nodeHTTPAddress string
	apiKey          string

	gasLimit int64
}

// NewEasyUtilsSDK 交易用sdk
func NewEasyUtilsSDK(nodeAddress string, nodeHTTPAddress string, token string, withTLS bool, gasLimit int64) (*EasyUtilsSDK, error) {
	conn := client.NewGrpcClient(nodeAddress + ":50051")

	// load grpc options
	opts := make([]grpc.DialOption, 0)
	if withTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// check for env API Key
	if trongridKey := os.Getenv("TRONGRID_APIKEY"); len(trongridKey) > 0 {
		token = trongridKey
	}

	// set API
	err := conn.SetAPIKey(token)
	if err != nil {
		return nil, err
	}

	if gasLimit == 0 {
		gasLimit = 1000000000
	}

	e := EasyUtilsSDK{
		conn:            conn,
		apiKey:          token,
		gasLimit:        gasLimit,
		nodeHTTPAddress: nodeHTTPAddress,
	}

	if err := conn.Start(opts...); err != nil {
		return nil, err
	}

	return &e, nil
}

// SignTx 簽名交易
func (e *EasyUtilsSDK) SignTx(privateKey *ecdsa.PrivateKey, tx *core.Transaction) (*core.Transaction, error) {
	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	tx.Signature = append(tx.Signature, signature)
	return tx, nil
}

// SendSignedTx 发送签名消息
func (e *EasyUtilsSDK) SendSignedTx(tx *core.Transaction) (*api.Return, error) {
	result, err := e.conn.Broadcast(tx)
	if err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("bad transaction: %v", string(result.GetMessage()))
	}

	return result, nil
}

// TxConfirmation 確認交易 (tx,查詢次數)
func (e *EasyUtilsSDK) TxConfirmation(tx *core.Transaction, numberQueries int) (*core.TransactionInfo, error) {
	txHash, err := e.TransactionHash(tx)
	if err != nil {
		return nil, err
	}

	if numberQueries == 0 {
		numberQueries = 2
	}

	var txi *core.TransactionInfo

	var errOut error
	for i := 0; i < numberQueries; i++ {
		txi, errOut = e.conn.GetTransactionInfoByID(txHash)
		if errOut != nil {
			time.Sleep(time.Second)
			continue
		}
		if txi.Result != 0 {
			errOut = fmt.Errorf("%s", txi.ResMessage)
			time.Sleep(time.Second)
			continue
		} else {
			errOut = nil
		}
	}

	return txi, errOut
}

// TxConfirmationByHash 確認交易 (tx,查詢次數)
func (e *EasyUtilsSDK) TxConfirmationByHash(txHash string, numberQueries int) (*core.TransactionInfo, error) {
	if numberQueries == 0 {
		numberQueries = 2
	}

	var txi *core.TransactionInfo

	var errOut error
	for i := 0; i < numberQueries; i++ {
		txi, errOut = e.conn.GetTransactionInfoByID(txHash)
		if errOut != nil {
			time.Sleep(time.Second)
			continue
		}
		if txi.Result != 0 {
			errOut = fmt.Errorf("%s", txi.ResMessage)
			time.Sleep(time.Second)
			continue
		} else {
			errOut = nil
		}
	}

	return txi, errOut
}

// TransactionHash 獲取tx id/hash
func (e *EasyUtilsSDK) TransactionHash(tx *core.Transaction) (string, error) {
	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return "", err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	return common.BytesToHexString(hash), nil
}

// SendTRXToAddress fromPrivateKey,toAddress string, value float,numberQueries 查詢交易是否成功次數
func (e *EasyUtilsSDK) SendTRXToAddress(privateKeyStr string, toAddress string, value float64, numberQueries int) (*core.Transaction, error) {
	privateKey, err := DecodePrivateKey(privateKeyStr)
	if err != nil {
		return nil, err
	}

	signerAddress, err := PublicKeyToTronAddress(privateKey.PubKey())
	if err != nil {
		return nil, err
	}

	valueInt := int64(value * math.Pow10(6))

	tx, err := e.conn.Transfer(signerAddress, toAddress, valueInt)
	if err != nil {
		return nil, err
	}

	signTx, err := e.SignTx(privateKey.ToECDSA(), tx.Transaction)
	if err != nil {
		return nil, err
	}

	_, err = e.SendSignedTx(signTx)
	if err != nil {
		return nil, err
	}

	if numberQueries == 0 {
		return signTx, err
	}
	_, err = e.TxConfirmation(signTx, numberQueries)
	return signTx, err
}

// Balance 獲取balance 新用戶沒有幣記錄會報用戶不存在
func (e *EasyUtilsSDK) Balance(address string) (*Balance, error) {
	acc, err := e.conn.GetAccount(address)
	if err != nil {
		return nil, err
	}

	b := Balance{
		Address:   address,
		Allowance: float64(acc.GetAllowance()) / 1000000,
		Balance:   float64(acc.GetBalance()) / 1000000,
		Type:      int(acc.GetType()),
	}

	return &b, nil
}

type Balance struct {
	Address   string  `json:"address"`
	Type      int     `json:"type"`
	Allowance float64 `json:"allowance"`
	Balance   float64 `json:"balance"`
}

func (b *Balance) Print() {
	indent, err := json.MarshalIndent(b, "", " ")
	if err == nil {
		fmt.Println(string(indent))
	}
}

// SendTRC20ToAddress 发送TRC20代币 (privateKeyStr, toAddress,contract string, value float64, numberQueries int)
func (e *EasyUtilsSDK) SendTRC20ToAddress(privateKeyStr string, toAddress string, contract string, value float64, numberQueries int) (*core.Transaction, error) {
	privateKey, err := DecodePrivateKey(privateKeyStr)
	if err != nil {
		return nil, err
	}

	signerAddress, err := PublicKeyToTronAddress(privateKey.PubKey())
	if err != nil {
		return nil, err
	}

	tokenDecimals, err := e.conn.TRC20GetDecimals(contract)
	if err != nil {
		tokenDecimals = big.NewInt(0)
	}

	amount, _ := decimals.ApplyDecimals(big.NewFloat(value), tokenDecimals.Int64())
	tx, err := e.conn.TRC20Send(signerAddress, toAddress, contract, amount, e.gasLimit)
	if err != nil {
		return nil, err
	}

	signTx, err := e.SignTx(privateKey.ToECDSA(), tx.Transaction)
	if err != nil {
		return nil, err
	}

	_, err = e.SendSignedTx(signTx)
	if err != nil {
		return nil, err
	}

	if numberQueries == 0 {
		return signTx, err
	}
	_, err = e.TxConfirmation(signTx, numberQueries)
	return signTx, err
}

// TRC20Balance 獲取TRC20代币余额
func (e *EasyUtilsSDK) TRC20Balance(address string, contract string) (float64, error) {
	tokenDecimals, err := e.conn.TRC20GetDecimals(contract)
	if err != nil {
		tokenDecimals = big.NewInt(0)
	}

	value, err := e.conn.TRC20ContractBalance(address, contract)
	if err != nil {
		return 0, err
	}

	amount := decimals.RemoveDecimals(value, tokenDecimals.Int64())
	f, _ := amount.Float64()

	return f, nil
}

// TRC20TransactionHistory 获取TRC20代币交易历史 (address, contract string 合於地址爲空則查詢全部trc20, limit int, onlyTo bool 只查入金, onlyFrom bool 之查詢出金)
func (e *EasyUtilsSDK) TRC20TransactionHistory(address string, contract string, limit int, onlyTo bool, onlyFrom bool) ([]TRC20TransactionHistoryItem, error) {
	client := resty.New()
	resp, err := client.R().
		SetQueryParams(map[string]string{
			"only_confirmed":   "true",
			"contract_address": contract,
			"limit":            fmt.Sprintf("%d", limit),
			"only_to":          fmt.Sprintf("%t", onlyTo),
			"only_from":        fmt.Sprintf("%t", onlyFrom),
		}).
		SetHeader("Accept", "application/json").
		SetHeader("TRON-PRO-API-KEY", e.apiKey).
		Get(fmt.Sprintf("%s/v1/accounts/%s/transactions/trc20", e.nodeHTTPAddress, address))
	if err != nil {
		return nil, err
	}

	var history _TRC20TransactionHistory
	err = json.Unmarshal(resp.Body(), &history)
	if err != nil {
		return nil, err
	}

	return history.Data, nil
}

type _TRC20TransactionHistory struct {
	Data    []TRC20TransactionHistoryItem `json:"data"`
	Success bool                          `json:"success"`
	Meta    struct {
		PageSize int   `json:"page_size"`
		At       int64 `json:"at"`
	} `json:"meta"`
}

type TRC20TransactionHistoryItem struct {
	TransactionId  string `json:"transaction_id"`
	BlockTimestamp int64  `json:"block_timestamp"`
	From           string `json:"from"`
	To             string `json:"to"`
	Value          string `json:"value"`
	Type           string `json:"type"`
	TokenInfo      struct {
		Name     string `json:"name"`
		Symbol   string `json:"symbol"`
		Decimals int    `json:"decimals"`
		Address  string `json:"address"`
	} `json:"token_info"`
}

func (e *EasyUtilsSDK) UnpackInput(txInput, abiJson string) ([]interface{}, string, error) {
	var data = make([]interface{}, 0)
	abi, err := abi.JSON(strings.NewReader(abiJson))
	if err != nil {
		return data, "", err
	}
	if len(txInput) > 8 {
		decodeSign, err := hex.DecodeString(txInput[0:8])
		if err != nil {
			return data, "", err
		}
		method, err := abi.MethodById(decodeSign)
		if err != nil {
			return data, "", err
		}
		decodedData, err := hex.DecodeString(txInput[8:])
		if err != nil {
			return data, "", err
		}
		// unpack method inputs
		data, err = method.Inputs.Unpack(decodedData)
		return data, method.Name, err
	}
	return data, "", errors.New("数据：" + txInput + "解析失败")
}

const StandardTokenABI = "[{\"inputs\":[{\"internalType\":\"string\",\"name\":\"name_\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"symbol_\",\"type\":\"string\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

func (e *EasyUtilsSDK) TRC20Tx(contract string, nodeChannel chan TxNode) {
	for {
		block, err := e.conn.GetNowBlock()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second)
			continue
		}

		if len(block.Transactions) == 0 {
			continue
		}

		for _, v := range block.Transactions {
			if v.Transaction == nil {
				continue
			}
			for _, v2 := range v.Transaction.RawData.Contract {
				if v2.Parameter.TypeUrl != "type.googleapis.com/protocol.TriggerSmartContract" {
					continue
				}

				tsc := core.TriggerSmartContract{}
				err := v2.Parameter.UnmarshalTo(&tsc)
				if err != nil {
					continue
				}

				if contract != "" {
					if address.HexToAddress(hex.EncodeToString(tsc.ContractAddress)).String() != contract {
						continue
					}
				}

				params, method, err := e.UnpackInput(hex.EncodeToString(tsc.Data), StandardTokenABI)
				if method != "transfer" {
					continue
				}
				toHex := params[0].(ethCommon.Address).Hex()
				decimals, err := e.conn.TRC20GetDecimals(address.HexToAddress(hex.EncodeToString(tsc.ContractAddress)).String())
				if err != nil {
					continue
				}
				f, _ := (params[1].(*big.Int)).Float64()

				nodeChannel <- TxNode{
					FromAddress: address.HexToAddress(hex.EncodeToString(tsc.OwnerAddress)).String(),
					ToAddress:   toHex,
					Contract:    address.HexToAddress(hex.EncodeToString(tsc.ContractAddress)).String(),
					Amount:      f / math.Pow(10, float64(decimals.Int64())),
				}
			}
		}

		time.Sleep(time.Second)
	}
}

type TxNode struct {
	FromAddress string
	ToAddress   string
	Contract    string
	Amount      float64
}

func (t *TxNode) Print() {
	indent, err := json.MarshalIndent(t, "", " ")
	if err == nil {
		fmt.Println(string(indent))
	}
}
