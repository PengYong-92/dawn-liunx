package main

import (
	"context"
	"fmt"
	"log"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

var (
	mintAuthority solana.PublicKey
	mintAccount   solana.PublicKey
	totalSupply   uint64 = 1000 // 定义代币的总量
	mintedAmount  uint64 = 0    // 已铸造的代币数量
)

func main() {
	// 连接到本地 Solana 节点
	rpcClient := rpc.New(rpc.MainNetBeta_RPC) // 使用主网或你本地的 RPC
	// 初始化 mintAuthority 和 mintAccount
	mintAuthority = solana.MustPublicKeyFromBase58("your_mint_authority_pubkey")
	mintAccount = solana.MustPublicKeyFromBase58("your_mint_account_pubkey")

	// 示例钱包地址
	wallet := solana.MustPublicKeyFromBase58("wallet_address")

	// 检查并执行 mint
	err := mintToken(rpcClient, wallet)
	if err != nil {
		log.Fatalf("failed to mint token: %v", err)
	}
}

// mintToken 为指定的钱包地址铸造代币
func mintToken(client *rpc.Client, wallet solana.PublicKey) error {
	if mintedAmount >= totalSupply {
		return fmt.Errorf("total supply limit reached")
	}

	// 检查钱包是否已经铸造过代币
	alreadyMinted, err := hasMintedBefore(client, wallet)
	if err != nil {
		return err
	}

	if alreadyMinted {
		return fmt.Errorf("wallet has already minted tokens")
	}

	// 分配剩余总量的代币（例如一次铸造 100 个）
	mintAmount := totalSupply / 10
	if mintAmount > totalSupply-mintedAmount {
		mintAmount = totalSupply - mintedAmount
	}

	// 获取最近的区块哈希
	recentBlockhashResp, err := client.GetRecentBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		return fmt.Errorf("failed to get recent blockhash: %v", err)
	}
	recentBlockhash := recentBlockhashResp.Value.Blockhash

	// 构建 MintTo 指令
	instruction := token.NewMintToInstruction(
		mintAmount,    // 要铸造的代币数量
		mintAccount,   // 代币 mint 账户
		wallet,        // 接收代币的钱包地址
		mintAuthority, // mint 权限账户
		nil,           // 如果没有多签名者，传递 nil
	).Build()
	// 构建交易
	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		recentBlockhash,                 // 使用刚刚获取的区块哈希
		solana.TransactionPayer(wallet), // 交易支付者
	)
	if err != nil {
		return err
	}

	// 发送交易
	_, err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		return err
	}

	// 更新已铸造的代币数量
	mintedAmount += mintAmount
	fmt.Printf("Minted %d tokens to wallet %s\n", mintAmount, wallet.String())

	return nil
}

// 检查钱包是否已经铸造过代币
func hasMintedBefore(client *rpc.Client, wallet solana.PublicKey) (bool, error) {
	// 构造 GetTokenAccountsOpts 对象，包含 CommitmentType
	opts := &rpc.GetTokenAccountsOpts{
		Commitment: rpc.CommitmentFinalized,
	}

	// 使用 RPC 查询该钱包是否有与该 mintAccount 相关的代币账户
	response, err := client.GetTokenAccountsByOwner(
		context.Background(),
		wallet, // 钱包地址
		&rpc.GetTokenAccountsConfig{
			Mint: &mintAccount, // 只查询与特定 Mint 账户相关的代币账户
		},
		opts, // 传递 opts
	)
	if err != nil {
		return false, fmt.Errorf("failed to get token accounts by owner: %v", err)
	}

	// 如果返回的代币账户数量大于 0，则说明该钱包已经持有该代币
	if len(response.Value) > 0 {
		return true, nil
	}
	return false, nil
}
