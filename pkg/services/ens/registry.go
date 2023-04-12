package ens

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens/contract/namehash"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens/contract/registry"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens/contract/resolver"
	"github.com/pkg/errors"
)

type Network string

var ListNetworks = map[string]Network{
	"MainNet": MainNet,
	"Robsten": Robsten,
}

// These addresses hard coded in blockchain.
const (
	MainNet Network = "00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
	Robsten Network = "00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
)

// Registry core contract in ENS.
type Registry struct {
	eth      *ethclient.Client
	contract *registry.Contract
	address  common.Address
}

// NewRegistry create interface for communication with core contract in ENS.
func NewRegistry(eth *ethclient.Client, network Network) (*Registry, error) {
	hexAddr := common.HexToAddress(string(network))
	contract, err := registry.NewContract(hexAddr, eth)
	if err != nil {
		return nil, errors.Wrap(err, "failed connect to registry")
	}

	return &Registry{
		eth:      eth,
		contract: contract,
		address:  hexAddr,
	}, nil
}

// Resolver return resolver for domain.
func (r *Registry) Resolver(domain string) (*Resolver, error) {
	hashedDomain, err := namehash.NameHash(domain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed get namehash for domain '%s': %s", domain, err)
	}
	resolverAddr, err := r.contract.Resolver(nil, hashedDomain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed get resolver for domain '%s': %s", domain, err)
	}

	contract, err := resolver.NewContract(resolverAddr, r.eth)
	if err != nil {
		return nil, errors.Wrapf(err, "failed create registry for contract '%s': %s", domain, err)
	}

	return &Resolver{
		client:   r.eth,
		contract: contract,
		address:  resolverAddr,
		domain:   hashedDomain,
	}, nil
}
