package eth

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/driver-did-polygonid/pkg/services"
	cm "github.com/iden3/driver-did-polygonid/pkg/services/blockchain/eth/contract/mock"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

var userDID, _ = core.ParseDID("did:polygonid:polygon:mumbai:2qJEaVmT5jBrtgBQ4m7b7bRYzWmvMyDjBZGP24QwvD")

func TestResolveGist_Success(t *testing.T) {
	tests := []struct {
		name             string
		opts             *services.ResolverOpts
		contractMock     func(c *cm.MockStateContract)
		expectedGistInfo *services.GistInfo
	}{
		{
			name: "resolve gist by root",
			opts: &services.ResolverOpts{
				GistRoot: big.NewInt(1),
			},
			contractMock: func(c *cm.MockStateContract) {
				res := abi.IStateGistRootInfo{Root: big.NewInt(2)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), big.NewInt(1)).Return(res, nil)
			},
			expectedGistInfo: &services.GistInfo{
				Root: big.NewInt(2),
			},
		},
		{
			name: "resolve latest gist",
			opts: &services.ResolverOpts{},
			contractMock: func(c *cm.MockStateContract) {
				latestRoot := big.NewInt(1)
				c.EXPECT().GetGISTRoot(gomock.Any()).Return(latestRoot, nil)
				res := abi.IStateGistRootInfo{Root: big.NewInt(2)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestRoot).Return(res, nil)
			},
			expectedGistInfo: &services.GistInfo{
				Root: big.NewInt(2),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			stateContract := cm.NewMockStateContract(ctrl)

			tt.contractMock(stateContract)
			resolver := Resolver{state: stateContract}
			gistInfo, err := resolver.ResolveGist(context.Background(), tt.opts)
			require.NoError(t, err)
			require.Equal(t, tt.expectedGistInfo, gistInfo)

			ctrl.Finish()
		})
	}
}

func TestResolve_Success(t *testing.T) {
	tests := []struct {
		name                  string
		opts                  *services.ResolverOpts
		userDID               *core.DID
		contractMock          func(c *cm.MockStateContract)
		expectedIdentityState services.IdentityState
	}{
		{
			name: "resolve identity state by gist",
			opts: &services.ResolverOpts{
				GistRoot: big.NewInt(1),
			},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				proof := abi.IStateGistProof{
					Root:      big.NewInt(4),
					Existence: true,
					Value:     big.NewInt(5),
				}
				c.EXPECT().GetGISTProofByRoot(gomock.Any(), userDID.ID.BigInt(), big.NewInt(1)).Return(proof, nil)
				gistInfo := abi.IStateGistRootInfo{Root: big.NewInt(555)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), big.NewInt(4)).Return(gistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userDID.ID.BigInt(), State: big.NewInt(444)}
				c.EXPECT().GetStateInfoByIdAndState(gomock.Any(), gomock.Any(), big.NewInt(5)).Return(stateInfo, nil)
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:    *userDID,
					State: big.NewInt(444),
				},
				GistInfo: &services.GistInfo{
					Root: big.NewInt(555),
				},
			},
		},
		{
			name: "resolve identity state by state",
			opts: &services.ResolverOpts{
				State: big.NewInt(1),
			},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				res := abi.IStateStateInfo{Id: userDID.ID.BigInt(), State: big.NewInt(555)}
				c.EXPECT().GetStateInfoByIdAndState(gomock.Any(), gomock.Any(), big.NewInt(1)).Return(res, nil)
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:    *userDID,
					State: big.NewInt(555),
				},
				GistInfo: nil,
			},
		},
		{
			name:    "resolve latest state",
			opts:    &services.ResolverOpts{},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				latestGist := big.NewInt(100)
				c.EXPECT().GetGISTRoot(gomock.Any()).Return(latestGist, nil)
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestGist).Return(latestGistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userDID.ID.BigInt(), State: big.NewInt(555)}
				c.EXPECT().GetStateInfoById(gomock.Any(), userDID.ID.BigInt()).Return(stateInfo, nil)
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:    *userDID,
					State: big.NewInt(555),
				},
				GistInfo: &services.GistInfo{
					Root: big.NewInt(400),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			stateContract := cm.NewMockStateContract(ctrl)

			tt.contractMock(stateContract)
			resolver := Resolver{state: stateContract}
			gistInfo, err := resolver.Resolve(context.Background(), *tt.userDID, tt.opts)
			require.NoError(t, err)
			require.Equal(t, tt.expectedIdentityState, gistInfo)

			ctrl.Finish()
		})
	}
}

func TestNotFoundErr(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedMessage string
		expectedType    error
	}{
		{
			name:            "gist root does not exist in the contract",
			err:             errors.New("execution reverted: Root does not exist"),
			expectedMessage: fmt.Sprintf("gist %s", services.ErrNotFound),
			expectedType:    services.ErrNotFound,
		},
		{
			name:            "identity does not exist in the contract",
			err:             errors.New("execution reverted: Identity does not exist"),
			expectedMessage: fmt.Sprintf("identity %s", services.ErrNotFound),
			expectedType:    services.ErrNotFound,
		},
		{
			name:            "state of identitty does not exist in the contract",
			err:             errors.New("execution reverted: State does not exist"),
			expectedMessage: fmt.Sprintf("state %s", services.ErrNotFound),
			expectedType:    services.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualErr := notFoundErr(tt.err)
			require.ErrorIs(t, actualErr, tt.expectedType)
			require.Equal(t, tt.expectedMessage, actualErr.Error())
		})
	}
}
