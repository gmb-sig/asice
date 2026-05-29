// Package asice assembles and inspects ASiC-E (.asice) containers
// holding XAdES signatures, per ETSI EN 319 162-1 (ASiC) and ETSI EN 319 132-1
// (XAdES).
//
// The package is deliberately framework-agnostic: it performs no network I/O,
// no authentication, and no HTTP. It also performs no cryptographic signature
// verification — that is delegated to an external validator (EU DSS).
// The checks here are over file digests and XAdES references only (hashing and
// XML reading), which keeps the dependency surface tiny.
//
// The four entry points mirror the service design:
//
//   - BuildContainer assembles a new .asice from documents + one or more XAdES
//     signature files.
//   - AddSignature adds a parallel (co-) signature to an existing .asice,
//     deriving the next signature file index itself.
//   - Inspect enumerates the manifest, signatures, and data objects in a
//     container.
//   - CheckReferences verifies that signature files reference exactly the
//     supplied documents (count, filename, and SHA-2 digest match).
package asice

import "errors"

// Container media type and well-known container paths.
const (
	// MimeType is the ASiC-E container media type. It is the value of the
	// uncompressed "mimetype" entry that must be first in the ZIP.
	MimeType = "application/vnd.etsi.asic-e+zip"

	mimetypePath = "mimetype"
	metaInfDir   = "META-INF/"
	manifestPath = "META-INF/manifest.xml"
)

// XML namespaces used when reading/writing container artefacts.
const (
	// nsXAdESSignatures is the ASiC namespace for the XAdESSignatures wrapper
	// element that holds detached ds:Signature elements.
	nsXAdESSignatures = "http://uri.etsi.org/02918/v1.2.1#"
	// nsDSig is the W3C XML-DSig namespace.
	nsDSig = "http://www.w3.org/2000/09/xmldsig#"
	// nsManifest is the OpenDocument manifest namespace used by the national
	// .asice profile.
	nsManifest = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
)

// File is a named blob: an original document or a signature file. Name is the
// in-container path (data objects live in the container root, so it is normally
// a bare filename) and Data is the raw bytes.
type File struct {
	Name string
	Data []byte
}

// BuildOptions tunes container assembly. The zero value is the recommended
// default: reference checks run and signatures are wrapped per signature file.
type BuildOptions struct {
	// SkipReferenceCheck disables the count/filename/digest verification that
	// BuildContainer runs before assembly. Leave false unless the caller has
	// already validated references via CheckReferences.
	SkipReferenceCheck bool
}

// Error codes reported by this package.
// Wrap-aware: use errors.Is against these sentinels.
var (
	// ErrFileCountMismatch: a signature references a different number of data
	// objects than the documents supplied.
	ErrFileCountMismatch = errors.New("asice: file count mismatch")
	// ErrFilenameMismatch: a supplied filename is not referenced by the
	// signature, or vice versa.
	ErrFilenameMismatch = errors.New("asice: filename mismatch")
	// ErrDigestMismatch: a supplied file's content does not match the digest
	// recorded in the signature.
	ErrDigestMismatch = errors.New("asice: digest mismatch")
	// ErrSignatureTargetMismatch: (parallel signing) the new signature signs
	// different data objects than the container already holds.
	ErrSignatureTargetMismatch = errors.New("asice: signature targets differ from container")
	// ErrMalformedXAdES: a signature file is not parseable as XAdES / contains
	// no ds:Signature.
	ErrMalformedXAdES = errors.New("asice: malformed XAdES signature")
	// ErrUnsupportedDigest: a ds:DigestMethod algorithm is not supported.
	ErrUnsupportedDigest = errors.New("asice: unsupported digest algorithm")
	// ErrInvalidContainer: the input bytes are not a readable ASiC-E container.
	ErrInvalidContainer = errors.New("asice: invalid container")
	// ErrNoSignatures: an operation requires at least one signature but none
	// were supplied.
	ErrNoSignatures = errors.New("asice: no signatures supplied")
	// ErrNoDocuments: an operation requires at least one document but none were
	// supplied.
	ErrNoDocuments = errors.New("asice: no documents supplied")
)
