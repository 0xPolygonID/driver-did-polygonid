package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-polygonid/pkg/app/configs"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-ens/v3"
)

const (
	gasLimit          = uint64(1000000)
	priceForENSRecord = 20000000000000000

	defaultDomain = "iden3.eth"
)

// We can't use reclaim for domain.
// Because test net doesn't support this functionality.
func main() {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		domain = defaultDomain
	}

	cfg, err := configs.ReadConfigFromFile()
	if err != nil {
		log.Fatalf("can't read config: %+v\n", err)
	}

	e, err := ethclient.Dial(cfg.Ens.EthNodeURL)
	if err != nil {
		log.Fatal("can't connect to eth network:", err)
	}

	privateKey, err := crypto.HexToECDSA(cfg.Ens.Owner)
	if err != nil {
		log.Fatal("failed parse private key:", err)
	}

	tx, err := RegistrationDomain(e, domain, privateKey)
	if err != nil {
		log.Fatal("failed registration domain:", err)
	} else if tx == nil {
		log.Println("domain already exists")
		os.Exit(0)
	}
}

func RegistrationDomain(eth *ethclient.Client, domain string, owner *ecdsa.PrivateKey) (*types.Transaction, error) {
	name, err := ens.NewName(eth, domain)
	if err != nil {
		return nil, err
	}

	exist, err := name.IsRegistered()
	if err != nil {
		return nil, err
	}

	if exist {
		return nil, nil
	}

	var secret [32]byte

	tx, err := AuthCall(eth, 0, owner, func(client *ethclient.Client, opts *bind.TransactOpts) (*types.Transaction, error) {
		owner := crypto.PubkeyToAddress(owner.PublicKey)
		var (
			tx  *types.Transaction
			err error
		)

		tx, secret, err = name.RegisterStageOne(owner, opts)

		return tx, err
	})
	if err != nil {
		return nil, err
	}
	log.Println("finish first step of registration:", tx.Hash())

	wait, err := name.RegistrationInterval()
	if err != nil {
		return nil, err
	}

	// add an additional pause for default waiting interval.
	// Because default interval is not enough.
	t := time.NewTicker(wait + time.Second*30)
	<-t.C

	tx, err = AuthCall(eth, priceForENSRecord, owner, func(client *ethclient.Client, opts *bind.TransactOpts) (*types.Transaction, error) {
		owner := crypto.PubkeyToAddress(owner.PublicKey)
		return name.RegisterStageTwo(owner, secret, opts)
	})
	if err != nil {
		return nil, err
	}
	done := waitTx(eth, tx)
	err = <-done
	if err != nil {
		log.Fatal("waiting transaction failed:", err)
	}
	log.Println("finish second step of registration:", tx.Hash())

	// Set default resolver.
	tx, err = AuthCall(eth, 0, owner, func(client *ethclient.Client, opts *bind.TransactOpts) (*types.Transaction, error) {
		return name.SetResolverAddress(common.HexToAddress("42d63ae25990889e35f215bc95884039ba354115"), opts)
	})
	if err != nil {
		return nil, err
	}
	done = waitTx(eth, tx)
	err = <-done
	if err != nil {
		log.Fatal("waiting transaction failed:", err)
	}
	log.Println("finish set default resolver:", tx.Hash())

	resolver, err := ens.NewResolver(eth, domain)
	if err != nil {
		log.Fatal("failed create resolver:", err)
	}

	tx, err = AuthCall(eth, 0, owner, func(client *ethclient.Client, opts *bind.TransactOpts) (*types.Transaction, error) {
		return resolver.SetText(opts, "description", "did:iden3:eth:ropsten:11CX7U1dj8Fp9Vazr6QZTobKEUtYbg89DjmvkRVzd4")
	})
	if err != nil {
		log.Fatal("failed set text field:", err)
	}
	done = waitTx(eth, tx)
	err = <-done
	if err != nil {
		log.Fatal("waiting transaction failed:", err)
	}
	log.Println("finish set text record:", tx.Hash())

	log.Println(domain, "succeed registered")
	return tx, nil
}

func AuthCall(eth *ethclient.Client, value int64, privateKey *ecdsa.PrivateKey,
	fn func(client *ethclient.Client, opts *bind.TransactOpts) (*types.Transaction, error)) (*types.Transaction, error) {
	if privateKey == nil {
		return nil, errors.New("empty private key")
	}

	gasPrice, err := eth.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	inc := new(big.Int).Set(gasPrice)
	inc.Div(inc, new(big.Int).SetUint64(10))
	gasPrice.Add(gasPrice, inc)

	cid, err := eth.ChainID(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed return chainID")
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, cid)
	if err != nil {
		return nil, errors.Wrap(err, "failed create transaction signer")
	}
	auth.GasLimit = gasLimit // in wei
	auth.GasPrice = gasPrice // in gwei
	auth.Value = big.NewInt(value)

	return fn(eth, auth)
}

func waitTx(eth *ethclient.Client, tx *types.Transaction) <-chan error {
	done := make(chan error)

	go func() {
		for {
			receipt, err := eth.TransactionReceipt(context.Background(), tx.Hash())
			if err != nil && !errors.Is(err, ethereum.NotFound) {
				done <- err
				return
			}
			if receipt != nil && receipt.Status == 1 {
				done <- nil
			}
		}
	}()

	return done
}
