package ens

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens/contract/namehash"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens/contract/resolver"
	"github.com/pkg/errors"
)

// Resolver has interfaces for getting information about your domain.
type Resolver struct {
	client   *ethclient.Client
	contract *resolver.Contract
	domain   [32]byte
	address  common.Address
}

// NewResolver create interface for communication with resolver.
// 'address' this is address to your resolver.
// 'domain' this is the domain that is served by the resolver from the 'address' field.
func NewResolver(eth *ethclient.Client, address, domain string) (*Resolver, error) {
	contract, err := resolver.NewContract(common.HexToAddress(address), eth)
	if err != nil {
		return nil, errors.Wrap(err, "failed connect to resolver")
	}

	raw, err := namehash.NameHash(domain)
	if err != nil {
		return nil, err
	}

	return &Resolver{
		client:   eth,
		contract: contract,
		domain:   raw,
		address:  common.HexToAddress(address),
	}, nil
}

// Text return string that exist in domain txt record.
// https://eips.ethereum.org/EIPS/eip-634
func (r *Resolver) Text(key string) (string, error) {
	t, err := r.contract.Text(nil, r.domain, key)
	return t, errors.Wrapf(err, "failed return text from field '%s' for domain '%s'", key, r.domain)
}
