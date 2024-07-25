package document

import (
	"time"

	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type ErrorCode string

const (
	ErrInvalidDID         ErrorCode = "invalidDid"
	ErrMethodNotSupported ErrorCode = "methodNotSupported"
	ErrNotFound           ErrorCode = "notFound"
	ErrUnknownNetwork     ErrorCode = "unknownNetwork"

	StateType                            = "Iden3StateInfo2023"
	Iden3ResolutionMetadataType          = "Iden3ResolutionMetadata"
	EcdsaSecp256k1RecoveryMethod2020Type = "EcdsaSecp256k1RecoveryMethod2020"
)

const (
	defaultContext         = "https://w3id.org/did-resolution/v1"
	defaultDidDocContext   = "https://www.w3.org/ns/did/v1"
	iden3Context           = "https://schema.iden3.io/core/jsonld/auth.jsonld"
	defaultContentType     = "application/did+ld+json"
	iden3ResolutionContext = "https://schema.iden3.io/core/jsonld/resolution.jsonld"
	eip712sigContext       = "https://w3id.org/security/suites/eip712sig-2021/v1"
)

// DidResolution representation of did resolution.
type DidResolution struct {
	Context     string                  `json:"@context,omitempty"`
	DidDocument *verifiable.DIDDocument `json:"didDocument"`
	// should exist in responses, but can be empty.
	// https://www.w3.org/TR/did-core/#did-resolution
	DidResolutionMetadata *DidResolutionMetadata `json:"didResolutionMetadata"`
	DidDocumentMetadata   *DidDocumentMetadata   `json:"didDocumentMetadata"`
}

// NewDidResolution create did resolution with default values.
func NewDidResolution() *DidResolution {
	return &DidResolution{
		Context: defaultContext,
		DidDocument: &verifiable.DIDDocument{
			Context:            []string{defaultDidDocContext, iden3Context},
			VerificationMethod: []verifiable.CommonVerificationMethod{},
		},
		DidResolutionMetadata: &DidResolutionMetadata{
			ContentType: defaultContentType,
			Retrieved:   time.Now(),
		},
		DidDocumentMetadata: &DidDocumentMetadata{},
	}
}

func DidResolutionMetadataSigContext() []string {
	return []string{iden3ResolutionContext, eip712sigContext}
}

func NewDidMethodNotSupportedResolution(msg string) *DidResolution {
	return NewDidErrorResolution(ErrMethodNotSupported, msg)
}

func NewDidInvalidResolution(msg string) *DidResolution {
	return NewDidErrorResolution(ErrInvalidDID, msg)
}

func NewNetworkNotSupportedForDID(msg string) *DidResolution {
	return NewDidErrorResolution(ErrUnknownNetwork, msg)
}

func NewDidNotFoundResolution(msg string) *DidResolution {
	return NewDidErrorResolution(ErrNotFound, msg)
}

func NewDidErrorResolution(errCode ErrorCode, errMsg string) *DidResolution {
	return &DidResolution{
		DidResolutionMetadata: &DidResolutionMetadata{
			Error:     errCode,
			Message:   errMsg,
			Retrieved: time.Now(),
		},
		DidDocumentMetadata: &DidDocumentMetadata{},
	}
}

// DidResolutionMetadata representation of resolution metadata.
type DidResolutionMetadata struct {
	Context     interface{}         `json:"@context,omitempty"`
	Error       ErrorCode           `json:"error,omitempty"`
	Message     string              `json:"message,omitempty"`
	ContentType string              `json:"contentType,omitempty"`
	Retrieved   time.Time           `json:"retrieved,omitempty"`
	Type        string              `json:"type,omitempty"`
	Proof       DidResolutionProofs `json:"proof,omitempty"`
}

// DidDocumentMetadata metadata of did document.
type DidDocumentMetadata struct{}
