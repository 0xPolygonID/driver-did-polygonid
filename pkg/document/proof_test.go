package document

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/stretchr/testify/require"
)

func TestEthereumEip712SignatureProof2021_JSONUnmarshal(t *testing.T) {
	in := `{
  "type": "EthereumEip712Signature2021",
	"proofPurpose": "assertionMethod",
	"proofValue": "0xd5e5ffe290a258116a0f7acb4c9a5bbfdd842516061c6a794892b6db05fbd14706de7e189d965bead2ffb23e30d2f6b02ecf764e6fe24be788721049b7e331481c",
	"verificationMethod": "did:pkh:eip155:1:0x5b18eF56aA61eeAE0E3434e3c3d8AEB19b141fe7#blockchainAccountId",
	"created": "2021-09-23T20:21:34Z",
	"eip712": {
			"types": {
				"EIP712Domain": [
					{ "name": "name", "type": "string" },
					{ "name": "version", "type": "string" },
					{ "name": "chainId", "type": "uint256" },
					{ "name": "verifyingContract", "type": "address" }
				],
				"IdentityState": [
					{ "name": "from", "type": "address" },
					{ "name": "timestamp", "type": "uint256" },
					{ "name": "state", "type": "uint256" },
					{ "name": "stateCreatedAtTimestamp", "type": "uint256" },
					{ "name": "stateReplacedAtTimestamp", "type": "uint256" },
					{ "name": "gistRoot", "type": "uint256" },
					{ "name": "gistRootCreatedAtTimestamp", "type": "uint256" },
					{ "name": "gistRootReplacedAtTimestamp", "type": "uint256" },
					{ "name": "identity", "type": "uint256" }
				]
			},
			"primaryType": "IdentityState",
			"domain": {
				"name": "StateInfo",
				"version": "1",
				"chainId": "0x1",
				"verifyingContract": "0x0000000000000000000000000000000000000000"
			},
			"message": {
				"from": "0x5b18eF56aA61eeAE0E3434e3c3d8AEB19b141fe7",
				"timestamp": "0",
				"state": "444",
				"stateCreatedAtTimestamp": "0",
				"stateReplacedAtTimestamp": "0",
				"gistRoot": "555",				
				"gistRootCreatedAtTimestamp": "0",				
				"gistRootReplacedAtTimestamp": "0",				
				"identity": "19090607534999372304474213543962416547920895595808567155882840509226423042"
			}
		}
	}`
	var proof EthereumEip712SignatureProof2021
	err := json.Unmarshal([]byte(in), &proof)
	require.NoError(t, err)

	timeParsed, _ := time.Parse("2006-01-02T15:04:05Z", "2021-09-23T20:21:34Z")

	var apiTypes = apitypes.Types{
		"IdentityState": []apitypes.Type{
			{Name: "from", Type: "address"},
			{Name: "timestamp", Type: "uint256"},
			{Name: "state", Type: "uint256"},
			{Name: "stateCreatedAtTimestamp", Type: "uint256"},
			{Name: "stateReplacedAtTimestamp", Type: "uint256"},
			{Name: "gistRoot", Type: "uint256"},
			{Name: "gistRootCreatedAtTimestamp", Type: "uint256"},
			{Name: "gistRootReplacedAtTimestamp", Type: "uint256"},
			{Name: "identity", Type: "uint256"},
		},
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
	}

	var primaryType = "IdentityState"
	walletAddress := "0x5b18eF56aA61eeAE0E3434e3c3d8AEB19b141fe7"
	state := "444"
	stateCreatedAtTimestamp := "0"
	stateReplacedAtTimestamp := "0"
	gistRootCreatedAtTimestamp := "0"
	gistRootReplacedAtTimestamp := "0"
	timestamp := "0"
	gistRoot := "555"
	identity := "19090607534999372304474213543962416547920895595808567155882840509226423042"
	chainID := 1

	wantProof := EthereumEip712SignatureProof2021{
		Type:               "EthereumEip712Signature2021",
		ProofPursopose:     "assertionMethod",
		ProofValue:         "0xd5e5ffe290a258116a0f7acb4c9a5bbfdd842516061c6a794892b6db05fbd14706de7e189d965bead2ffb23e30d2f6b02ecf764e6fe24be788721049b7e331481c",
		VerificationMethod: "did:pkh:eip155:1:0x5b18eF56aA61eeAE0E3434e3c3d8AEB19b141fe7#blockchainAccountId",
		Created:            timeParsed,
		Eip712: apitypes.TypedData{
			Types:       apiTypes,
			PrimaryType: primaryType,
			Domain: apitypes.TypedDataDomain{
				Name:              "StateInfo",
				Version:           "1",
				ChainId:           math.NewHexOrDecimal256(int64(chainID)),
				VerifyingContract: "0x0000000000000000000000000000000000000000",
			},
			Message: apitypes.TypedDataMessage{
				"from":                        walletAddress,
				"timestamp":                   timestamp,
				"state":                       state,
				"stateCreatedAtTimestamp":     stateCreatedAtTimestamp,
				"stateReplacedAtTimestamp":    stateReplacedAtTimestamp,
				"gistRoot":                    gistRoot,
				"gistRootCreatedAtTimestamp":  gistRootCreatedAtTimestamp,
				"gistRootReplacedAtTimestamp": gistRootReplacedAtTimestamp,
				"identity":                    identity,
			},
		},
	}
	require.Equal(t, wantProof, proof)
}
