package services

import (
	"context"
	"fmt"
	"math/big"
	"net"

	"github.com/iden3/driver-did-polygonid/pkg/document"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/pkg/errors"
)

const (
	ensResolverKey = "description"
)

type DidDocumentServices struct {
	resolvers *ResolverRegistry
	ens       *ens.Registry
}

type ResolverOpts struct {
	State    *big.Int
	GistRoot *big.Int
}

func NewDidDocumentServices(resolvers *ResolverRegistry, registry *ens.Registry) *DidDocumentServices {
	return &DidDocumentServices{resolvers, registry}
}

// GetDidDocument return did document by identifier.
func (d *DidDocumentServices) GetDidDocument(ctx context.Context, did string, opts *ResolverOpts) (*document.DidResolution, error) {
	if opts == nil {
		opts = &ResolverOpts{}
	}

	userDID, err := w3c.ParseDID(did)
	errResolution, err := expectedError(err)
	if err != nil {
		return errResolution, err
	}

	userID, err := core.IDFromDID(*userDID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	b, err := core.BlockchainFromID(userID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	n, err := core.NetworkIDFromID(userID)
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	resolver, err := d.resolvers.GetResolverByNetwork(string(b), string(n))
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	identityState, err := resolver.Resolve(ctx, *userDID, opts)
	if errors.Is(err, ErrNotFound) && (opts.State != nil || opts.GistRoot != nil) {
		gen, errr := isGenesis(userID.BigInt(), opts.State)
		if errr != nil {
			return nil, fmt.Errorf("invalid state: %v", errr)
		}
		if !gen {
			return document.NewDidNotFoundResolution(err.Error()), nil
		}
	}

	info, err := identityState.StateInfo.ToDidRepresentation()
	if err != nil {
		return nil, fmt.Errorf("invalid resolver response: %v", err)
	}

	gist, err := identityState.GistInfo.ToDidRepresentation()
	if err != nil {
		return nil, fmt.Errorf("invalid resolver response: %v", err)
	}

	didResolution := document.NewDidResolution()
	didResolution.DidDocument.ID = did
	didResolution.DidDocument.VerificationMethod = append(
		didResolution.DidDocument.VerificationMethod,
		document.VerificationMethod{
			ID:         fmt.Sprintf("%s#stateInfo", did),
			Type:       document.StateType,
			Controller: did,
			IdentityState: document.IdentityState{
				StateContractAddress: resolver.BlockchainID(),
				Published:            isPublished(identityState.StateInfo),
				Info:                 info,
				Global:               gist,
			},
		},
	)

	return didResolution, nil
}

// ResolveDNSDomain return did document by domain via DNS.
func (d *DidDocumentServices) ResolveDNSDomain(ctx context.Context, domain string) (*document.DidResolution, error) {
	domain = fmt.Sprintf("_did.%s", domain)
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed lookup domain '%s'", domain)
	}

	if len(records) == 0 {
		return nil, errors.Errorf("domain '%s' doesn't contain text fields", domain)
	}

	var (
		did *w3c.DID
		v   string
	)
	// try to find correct did.
	for _, v = range records {
		did, err = w3c.ParseDID(v)
		if did != nil && err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	if did == nil {
		return nil, errors.Errorf("did not found for domain '%s'", domain)
	}

	return d.GetDidDocument(ctx, v, nil)
}

// ResolveENSDomain return did document via ENS resolver.
func (d *DidDocumentServices) ResolveENSDomain(ctx context.Context, domain string) (*document.DidResolution, error) {
	res, err := d.ens.Resolver(domain)
	if err != nil {
		return nil, err
	}

	did, err := res.Text(ensResolverKey)
	if err != nil {
		return nil, err
	}

	return d.GetDidDocument(ctx, did, nil)
}

func (d *DidDocumentServices) GetGist(ctx context.Context, chain, network string, opts *ResolverOpts) (*document.GistInfo, error) {
	if opts == nil {
		opts = &ResolverOpts{}
	}
	resolver, err := d.resolvers.GetResolverByNetwork(chain, network)
	if err != nil {
		return nil, err
	}

	gistInfo, err := resolver.ResolveGist(ctx, opts)
	if err != nil {
		return nil, err
	}
	return gistInfo.ToDidRepresentation()
}

func isPublished(si *StateInfo) bool {
	if si == nil || si.State == nil {
		return false
	}
	return si.State.Cmp(big.NewInt(0)) != 0
}

func isGenesis(id, state *big.Int) (bool, error) {
	if state == nil {
		return false, nil
	}

	isGenesis, err := core.CheckGenesisStateID(id, state)
	if err != nil {
		return false, err
	}

	return isGenesis, nil
}

func expectedError(err error) (*document.DidResolution, error) {
	if err == nil {
		return nil, nil
	}

	switch {
	case errors.Is(err, core.ErrIncorrectDID):
		return document.NewDidInvalidResolution(err.Error()), err
	case
		errors.Is(err, core.ErrBlockchainNotSupportedForDID),
		errors.Is(err, core.ErrNetworkNotSupportedForDID):

		return document.NewNetworkNotSupportedForDID(err.Error()), err
	case errors.Is(err, core.ErrDIDMethodNotSupported):
		return document.NewDidMethodNotSupportedResolution(err.Error()), err
	}

	return nil, err
}
