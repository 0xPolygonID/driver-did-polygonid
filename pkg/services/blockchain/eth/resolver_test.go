package eth

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/mock/gomock"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/driver-did-polygonid/pkg/services"
	cm "github.com/iden3/driver-did-polygonid/pkg/services/blockchain/eth/contract/mock"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var userDID, _ = w3c.ParseDID("did:polygonid:polygon:amoy:2qY71pSkdCsRetTHbUA4YqG7Hx63Ej2PeiJMzAdJ2V")

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
		userDID               *w3c.DID
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
				userID, _ := core.IDFromDID(*userDID)
				c.EXPECT().GetGISTProofByRoot(gomock.Any(), userID.BigInt(), big.NewInt(1)).Return(proof, nil)
				gistInfo := abi.IStateGistRootInfo{Root: big.NewInt(555)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), big.NewInt(4)).Return(gistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(444)}
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
				userID, _ := core.IDFromDID(*userDID)
				res := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555)}
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
				userID, _ := core.IDFromDID(*userDID)
				latestGist := big.NewInt(100)
				c.EXPECT().GetGISTRoot(gomock.Any()).Return(latestGist, nil)
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestGist).Return(latestGistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555)}
				c.EXPECT().GetStateInfoById(gomock.Any(), userID.BigInt()).Return(stateInfo, nil)
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
			identityState, err := resolver.Resolve(context.Background(), *tt.userDID, tt.opts)
			require.NoError(t, err)
			require.Equal(t, tt.expectedIdentityState, identityState)

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

func TestResolveSignature_Success(t *testing.T) {
	userEmptyDID, _ := w3c.ParseDID("did:polygonid:polygon:amoy:000000000000000000000000000000000000000000")

	tests := []struct {
		name                  string
		opts                  *services.ResolverOpts
		userDID               *w3c.DID
		contractMock          func(c *cm.MockStateContract)
		timeStamp             func() string
		expectedIdentityState services.IdentityState
	}{
		{
			name: "resolve identity state by gist",
			opts: &services.ResolverOpts{
				GistRoot:  big.NewInt(1),
				Signature: "EthereumEip712Signature2021",
			},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				proof := abi.IStateGistProof{
					Root:      big.NewInt(4),
					Existence: true,
					Value:     big.NewInt(5),
				}
				userID, _ := core.IDFromDID(*userDID)
				c.EXPECT().GetGISTProofByRoot(gomock.Any(), userID.BigInt(), big.NewInt(1)).Return(proof, nil)
				gistInfo := abi.IStateGistRootInfo{Root: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedByRoot: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), big.NewInt(4)).Return(gistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(444), CreatedAtTimestamp: big.NewInt(0), ReplacedByState: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetStateInfoByIdAndState(gomock.Any(), gomock.Any(), big.NewInt(5)).Return(stateInfo, nil)
			},
			timeStamp: func() string {
				return "0"
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:                  *userDID,
					State:               big.NewInt(444),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByState:     big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo: &services.GistInfo{
					Root:                big.NewInt(555),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByRoot:      big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0xedbe6cd15241ee8cd6a76446fbdf44e90df28c42eaff606ea6cd55d97158c036187aad5556753bd7a306cd71bdaddfac7af7f4127b66e4159d3d6d69548ba4de1c",
			},
		},
		{
			name: "resolve identity state by state",
			opts: &services.ResolverOpts{
				State:     big.NewInt(1),
				Signature: "EthereumEip712Signature2021",
			},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				userID, _ := core.IDFromDID(*userDID)
				res := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedByState: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetStateInfoByIdAndState(gomock.Any(), gomock.Any(), big.NewInt(1)).Return(res, nil)
			},
			timeStamp: func() string {
				return "0"
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:                  *userDID,
					State:               big.NewInt(555),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByState:     big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo:  nil,
				Signature: "0x3fe7236be270e37125e265ced2b5be614909015d9636c7bca14e9adca38a9b5e789cedaa32edec24b9c1226df1ed4d86dafa8ab1587fb6d29b07e040dfb1b2861c",
			},
		},
		{
			name: "resolve latest state",
			opts: &services.ResolverOpts{
				Signature: "EthereumEip712Signature2021",
			},
			userDID: userDID,
			contractMock: func(c *cm.MockStateContract) {
				userID, _ := core.IDFromDID(*userDID)
				latestGist := big.NewInt(100)
				c.EXPECT().GetGISTRoot(gomock.Any()).Return(latestGist, nil)
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400), CreatedAtTimestamp: big.NewInt(0), ReplacedByRoot: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestGist).Return(latestGistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedByState: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetStateInfoById(gomock.Any(), userID.BigInt()).Return(stateInfo, nil)
			},
			timeStamp: func() string {
				return "0"
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: &services.StateInfo{
					ID:                  *userDID,
					State:               big.NewInt(555),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByState:     big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo: &services.GistInfo{
					Root:                big.NewInt(400),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByRoot:      big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0x8a39cf242b4474f62ad3579c31ae42e5981c0237fe6232513528f2731defc3db553535f23895a7d444d31a7643924071ce34f8a3dd308bfcbf1d4a90eb6ee5571c",
			},
		},
		{
			name: "resolve only gist",
			opts: &services.ResolverOpts{
				GistRoot:  big.NewInt(400),
				Signature: "EthereumEip712Signature2021",
			},
			userDID: userEmptyDID,
			contractMock: func(c *cm.MockStateContract) {
				latestGist := big.NewInt(400)
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400), CreatedAtTimestamp: big.NewInt(0), ReplacedByRoot: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestGist).Return(latestGistInfo, nil)
			},
			timeStamp: func() string {
				return "0"
			},
			expectedIdentityState: services.IdentityState{
				StateInfo: nil,
				GistInfo: &services.GistInfo{
					Root:                big.NewInt(400),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedByRoot:      big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0xb38e057dddbb4636ecf7a8f9d1eefc352ee0c8e395857462859509d9e40c68bf731e285117f571f5805bcbc6fb13a16fadd83d963d8a3918a793cf8877a363481b",
			},
		},
	}

	mnemonic := "rib satisfy drastic trigger trial exclude raccoon wedding then gaze fire hero"
	seed := bip39.NewSeed(mnemonic, "Secret Passphrase bla bla bla")
	masterPrivateKey, _ := bip32.NewMasterKey(seed)
	ecdaPrivateKey := crypto.ToECDSAUnsafe(masterPrivateKey.Key)
	privateKeyHex := fmt.Sprintf("%x", ecdaPrivateKey.D)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			stateContract := cm.NewMockStateContract(ctrl)
			tt.contractMock(stateContract)
			TimeStamp = tt.timeStamp
			resolver := Resolver{state: stateContract, chainID: 1, walletKey: privateKeyHex}
			identityState, err := resolver.Resolve(context.Background(), *tt.userDID, tt.opts)
			require.NoError(t, err)
			require.Equal(t, tt.expectedIdentityState, identityState)

			ok, _ := resolver.VerifyIdentityState(identityState, *tt.userDID)
			require.Equal(t, true, ok)
			ctrl.Finish()
		})
	}
}
