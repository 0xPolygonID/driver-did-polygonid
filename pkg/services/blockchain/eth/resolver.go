package eth

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/driver-did-polygonid/pkg/services"
	core "github.com/iden3/go-iden3-core"
)

//go:generate mockgen -destination=contract/mock/contract.go . StateContract
type StateContract interface {
	GetGISTRoot(opts *bind.CallOpts) (*big.Int, error)
	GetGISTRootInfo(opts *bind.CallOpts, root *big.Int) (abi.IStateGistRootInfo, error)
	GetGISTProofByRoot(opts *bind.CallOpts, id *big.Int, root *big.Int) (abi.IStateGistProof, error)

	GetStateInfoById(opts *bind.CallOpts, id *big.Int) (abi.IStateStateInfo, error)
	GetStateInfoByIdAndState(opts *bind.CallOpts, id, state *big.Int) (abi.IStateStateInfo, error)
}

type Resolver struct {
	state StateContract

	contractAddress string
	chainID         int
}

var (
	gistNotFoundException     = "execution reverted: Root does not exist"
	identityNotFoundException = "execution reverted: Identity does not exist"
	stateNotFoundException    = "execution reverted: State does not exist"
)

// NewResolver create new ethereum resolver.
func NewResolver(url, address string) (*Resolver, error) {
	c, err := ethclient.Dial(url)
	if err != nil {
		return nil, err
	}
	sc, err := abi.NewState(common.HexToAddress(address), c)
	if err != nil {
		return nil, err
	}

	resolver := &Resolver{
		state:           sc,
		contractAddress: address,
	}
	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	resolver.chainID = int(chainID.Int64())
	return resolver, nil
}

func (r *Resolver) BlockchainID() string {
	return fmt.Sprintf("%d:%s", r.chainID, r.contractAddress)
}

func (r *Resolver) ResolveGist(
	ctx context.Context,
	opts *services.ResolverOpts,
) (*services.GistInfo, error) {
	var err error

	gistRoot := opts.GistRoot
	if gistRoot == nil {
		gistRoot, err = r.state.GetGISTRoot(&bind.CallOpts{Context: ctx})
		if err != nil {
			return nil, err
		}
	}

	rootInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, gistRoot)
	if err = notFoundErr(err); err != nil {
		return nil, err
	}

	return &services.GistInfo{
		Root:                rootInfo.Root,
		ReplacedByRoot:      rootInfo.ReplacedByRoot,
		CreatedAtTimestamp:  rootInfo.CreatedAtTimestamp,
		ReplacedAtTimestamp: rootInfo.ReplacedAtTimestamp,
		CreatedAtBlock:      rootInfo.CreatedAtBlock,
		ReplacedAtBlock:     rootInfo.ReplacedAtBlock,
	}, nil
}

func (r *Resolver) Resolve(
	ctx context.Context,
	did core.DID,
	opts *services.ResolverOpts,
) (services.IdentityState, error) {
	if opts.GistRoot != nil && opts.State != nil {
		return services.IdentityState{},
			errors.New("options GistRoot and State together are not available")
	}

	var (
		stateInfo *abi.IStateStateInfo
		gistInfo  *abi.IStateGistRootInfo
		err       error
	)

	switch {
	case opts.GistRoot != nil:
		stateInfo, gistInfo, err = r.resolveStateByGistRoot(ctx, did.ID, opts.GistRoot)
	case opts.State != nil:
		stateInfo, err = r.resolveState(ctx, did.ID, opts.State)
	default:
		stateInfo, gistInfo, err = r.resolveLatest(ctx, did.ID)
	}

	identityState := services.IdentityState{}
	if stateInfo != nil {
		identityState.StateInfo = &services.StateInfo{
			ID:                  did,
			State:               stateInfo.State,
			ReplacedByState:     stateInfo.ReplacedByState,
			CreatedAtTimestamp:  stateInfo.CreatedAtTimestamp,
			ReplacedAtTimestamp: stateInfo.ReplacedAtTimestamp,
			CreatedAtBlock:      stateInfo.CreatedAtBlock,
			ReplacedAtBlock:     stateInfo.ReplacedAtBlock,
		}
	}
	if gistInfo != nil {
		identityState.GistInfo = &services.GistInfo{
			Root:                gistInfo.Root,
			ReplacedByRoot:      gistInfo.ReplacedByRoot,
			CreatedAtTimestamp:  gistInfo.CreatedAtTimestamp,
			ReplacedAtTimestamp: gistInfo.ReplacedAtTimestamp,
			CreatedAtBlock:      gistInfo.CreatedAtBlock,
			ReplacedAtBlock:     gistInfo.ReplacedAtBlock,
		}
	}

	return identityState, err
}

func (r *Resolver) resolveLatest(
	ctx context.Context,
	id core.ID,
) (*abi.IStateStateInfo, *abi.IStateGistRootInfo, error) {
	latestRootGist, err := r.state.GetGISTRoot(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, nil, err
	}
	gistInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, latestRootGist)
	if err != nil {
		return nil, nil, err
	}

	stateInfo, err := r.state.GetStateInfoById(&bind.CallOpts{Context: ctx}, id.BigInt())
	if err = notFoundErr(err); err != nil {
		return nil, &gistInfo, err
	}

	return &stateInfo, &gistInfo, verifyContractState(id, stateInfo)
}

func (r *Resolver) resolveState(
	ctx context.Context,
	id core.ID,
	state *big.Int,
) (*abi.IStateStateInfo, error) {
	stateInfo, err := r.state.GetStateInfoByIdAndState(
		&bind.CallOpts{Context: ctx}, id.BigInt(), state)
	if err = notFoundErr(err); err != nil {
		return nil, err
	}

	return &stateInfo, verifyContractState(id, stateInfo)
}

func (r *Resolver) resolveStateByGistRoot(
	ctx context.Context,
	id core.ID,
	gistRoot *big.Int,
) (*abi.IStateStateInfo, *abi.IStateGistRootInfo, error) {
	proof, err := r.state.GetGISTProofByRoot(
		&bind.CallOpts{Context: ctx},
		id.BigInt(),
		gistRoot,
	)
	if err := notFoundErr(err); err != nil {
		return nil, nil, err
	}
	gistInfo, err := r.state.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, proof.Root)
	if err = notFoundErr(err); err != nil {
		return nil, nil, err
	}

	if !proof.Existence {
		return nil, &gistInfo, nil
	}

	stateInfo, err := r.state.GetStateInfoByIdAndState(
		&bind.CallOpts{Context: ctx}, id.BigInt(), proof.Value)
	if err = notFoundErr(err); err != nil {
		return nil, &gistInfo, err
	}

	return &stateInfo, &gistInfo, verifyContractState(id, stateInfo)
}

func verifyContractState(id core.ID, state abi.IStateStateInfo) error {
	if state.Id.Cmp(id.BigInt()) != 0 {
		return fmt.Errorf("expected id '%s' not equal id '%s' from contract",
			id, state.Id)
	}
	return nil
}

func notFoundErr(err error) error {
	if err == nil {
		return nil
	}

	switch err.Error() {
	case gistNotFoundException:
		return fmt.Errorf("gist %w", services.ErrNotFound)
	case identityNotFoundException:
		return fmt.Errorf("identity %w", services.ErrNotFound)
	case stateNotFoundException:
		return fmt.Errorf("state %w", services.ErrNotFound)
	}

	return err
}
