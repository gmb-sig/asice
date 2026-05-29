package asice

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

// digestAlgorithms maps XML-DSig / xmlenc DigestMethod algorithm URIs to a hash
// constructor. ASiC-E in our profile is SHA-2 based; SHA-1 is included only so
// that legacy signatures can be inspected (it is not recommended for new ones).
var digestAlgorithms = map[string]func() hash.Hash{
	"http://www.w3.org/2000/09/xmldsig#sha1":        sha1.New,
	"http://www.w3.org/2001/04/xmlenc#sha256":       sha256.New,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": sha512.New384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       sha512.New,
}

// newHash returns a fresh hash for the given DigestMethod algorithm URI, or an
// error wrapping ErrUnsupportedDigest.
func newHash(algorithm string) (hash.Hash, error) {
	if ctor, ok := digestAlgorithms[algorithm]; ok {
		return ctor(), nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedDigest, algorithm)
}

// digestBase64 hashes data with the named DigestMethod algorithm and returns the
// base64-encoded digest, matching the encoding of ds:DigestValue.
func digestBase64(algorithm string, data []byte) (string, error) {
	h, err := newHash(algorithm)
	if err != nil {
		return "", err
	}
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
