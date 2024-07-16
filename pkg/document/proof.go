package document

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type DidResolutionProof interface {
	ProofType() verifiable.ProofType
}

type DidResolutionProofs []DidResolutionProof

type EthereumEip712SignatureProof2021 struct {
	Type               verifiable.ProofType `json:"type"`
	ProofPursopose     string               `json:"proofPurpose"`
	ProofValue         string               `json:"proofValue"`
	VerificationMethod string               `json:"verificationMethod"`
	Created            time.Time            `json:"created"`
	Eip712             apitypes.TypedData   `json:"eip712"`
}

// EthereumEip712Signature2021Type is a proof type for EIP172 signature proofs
const EthereumEip712SignatureProof2021Type verifiable.ProofType = "EthereumEip712Signature2021"

func (p *EthereumEip712SignatureProof2021) ProofType() verifiable.ProofType {
	return p.Type
}

func (p *EthereumEip712SignatureProof2021) UnmarshalJSON(in []byte) error {
	var obj struct {
		Type               verifiable.ProofType `json:"type"`
		ProofPursopose     string               `json:"proofPurpose"`
		ProofValue         string               `json:"proofValue"`
		VerificationMethod string               `json:"verificationMethod"`
		Created            time.Time            `json:"created"`
		Eip712             json.RawMessage      `json:"eip712"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return err
	}
	if obj.Type != EthereumEip712SignatureProof2021Type {
		return errors.New("invalid proof type")
	}
	p.Type = obj.Type
	err = json.Unmarshal(obj.Eip712, &p.Eip712)
	if err != nil {
		return err
	}
	p.VerificationMethod = obj.VerificationMethod
	p.ProofPursopose = obj.ProofPursopose
	// TODO: validate proof value
	p.ProofValue = obj.ProofValue
	p.Created = obj.Created
	return nil
}
