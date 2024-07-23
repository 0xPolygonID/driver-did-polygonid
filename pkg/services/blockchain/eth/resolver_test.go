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
				gistInfo := abi.IStateGistRootInfo{Root: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), big.NewInt(4)).Return(gistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(444), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
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
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo: &services.GistInfo{
					Root:                big.NewInt(555),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0xe63151912749d0cae7fea6a13dda6d54061626cc03a79dac46b6a11b3259c6c335d8266f09eaf070a31c8a23765fb01e3c8bf927f5ab25346f743ae309eabc801c",
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
				res := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
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
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo:  nil,
				Signature: "0x3dce5819f16b5225bbe9ec3ce144b45654119f4cfdff2f9e8f5d33a0fc3790de570dfacdc304ee217b43952c9393425fc45f5abc9e9f7e5b63196479319eb62c1b",
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
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
				c.EXPECT().GetGISTRootInfo(gomock.Any(), latestGist).Return(latestGistInfo, nil)
				stateInfo := abi.IStateStateInfo{Id: userID.BigInt(), State: big.NewInt(555), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
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
					ReplacedAtTimestamp: big.NewInt(0),
				},
				GistInfo: &services.GistInfo{
					Root:                big.NewInt(400),
					CreatedAtTimestamp:  big.NewInt(0),
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0x866206f5be01973be72631fd9931d8ccc7d6e8612f799dc39ff495d1e3a975af7c81c0e4fc13e50f4177fbc637e81ca546ee2906eccf1dfa96687fff05bd49831c",
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
				latestGistInfo := abi.IStateGistRootInfo{Root: big.NewInt(400), CreatedAtTimestamp: big.NewInt(0), ReplacedAtTimestamp: big.NewInt(0)}
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
					ReplacedAtTimestamp: big.NewInt(0),
				},
				Signature: "0xec3a8bd564247bed3c16f719d499e02d4914a8fa10704a8f3dcae75ca393b3ae47c3f147355f5476cb495b8e0463fd128da2795c02bd9420f8071d93652d13b81b",
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
