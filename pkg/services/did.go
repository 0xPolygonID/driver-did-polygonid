package services

import (
	"context"
	"fmt"
	"math/big"
	"net"

	"github.com/iden3/driver-did-polygonid/pkg/document"
	"github.com/iden3/driver-did-polygonid/pkg/services/ens"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
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

	userDID, err := core.ParseDID(did)
	errResolution, err := expectedError(err)
	if err != nil {
		return errResolution, err
	}

	resolver, err := d.resolvers.GetResolverByNetwork(string(userDID.Blockchain), string(userDID.NetworkID))
	errResolution, err = expectedError(err)
	if err != nil {
		return errResolution, err
	}

	identityState, err := resolver.Resolve(ctx, *userDID, opts)
	if errors.Is(err, ErrNotFound) && (opts.State != nil || opts.GistRoot != nil) {
		gen, errr := isGenesis(userDID.ID.BigInt(), opts.State)
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
	didResolution.DidDocument.Authentication = append(
		didResolution.DidDocument.Authentication,
		document.Authentication{
			ID:   getRepresentaionID(did, identityState),
			Type: document.StateType,
			IdentityState: document.IdentityState{
				BlockchainAccountID: resolver.BlockchainID(),
				Published:           isPublished(identityState.StateInfo),
				Info:                info,
				Global:              gist,
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
		did *core.DID
		v   string
	)
	// try to find correct did.
	for _, v = range records {
		did, err = core.ParseDID(v)
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

	userID, err := core.IDFromInt(id)
	if err != nil {
		return false, err
	}
	userDID, err := core.ParseDIDFromID(userID)
	if err != nil {
		return false, err
	}

	didType, err := core.BuildDIDType(userDID.Method, userDID.Blockchain, userDID.NetworkID)
	if err != nil {
		return false, err
	}
	identifier, err := core.IdGenesisFromIdenState(didType, state)
	if err != nil {
		return false, err
	}

	return id.Cmp(identifier.BigInt()) == 0, nil
}

func expectedError(err error) (*document.DidResolution, error) {
	if err == nil {
		return nil, nil
	}

	if errors.Is(err, core.ErrInvalidDID) {
		return document.NewDidInvalidResolution(err.Error()), err
	}
	if errors.Is(err, core.ErrNetworkNotSupportedForDID) {
		return document.NewNetworkNotSupportedForDID(err.Error()), err
	}
	if errors.Is(err, core.ErrDIDMethodNotSupported) {
		return document.NewDidMethodNotSupportedResolution(err.Error()), err
	}

	return nil, err
}

func getRepresentaionID(did string, state IdentityState) string {
	if state.StateInfo != nil && state.StateInfo.State != nil {
		h, _ := merkletree.NewHashFromBigInt(state.StateInfo.State)
		return fmt.Sprintf("%s?state=%s", did, h.Hex())
	}
	return did
}
