package asice

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
)

// signatureFileRE matches a META-INF signature file and captures its numeric
// index. A bare "signatures.xml" (no digits) is treated as index 0.
var signatureFileRE = regexp.MustCompile(`^META-INF/signatures(\d*)\.xml$`)

// signatureFileName returns the in-container path for the signature file at the
// given index, e.g. index 0 -> "META-INF/signatures0.xml".
func signatureFileName(index int) string {
	return fmt.Sprintf("%ssignatures%d.xml", metaInfDir, index)
}

// isSignatureFile reports whether an in-container path is a signature file.
func isSignatureFile(name string) bool {
	return signatureFileRE.MatchString(name)
}

// nextSignatureIndex derives the next free signature-file index by scanning the
// existing entry names: it returns one past the highest index in use, or
// 0 if there are no signature files yet. The caller never supplies the index.
func nextSignatureIndex(names []string) int {
	next := 0
	for _, n := range names {
		m := signatureFileRE.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		idx := 0
		if m[1] != "" {
			idx, _ = strconv.Atoi(m[1])
		}
		if idx+1 > next {
			next = idx + 1
		}
	}
	return next
}

// wrapSignature serialises a single ds:Signature as a standalone
// META-INF/signatures*.xml: a XAdESSignatures root (ASiC namespace) wrapping the
// signature's verbatim bytes. The signature bytes are embedded unchanged —
// parseSignatures already made them namespace-complete — so the signed content
// is preserved exactly.
func wrapSignature(ps parsedSignature) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(xml.Header) // <?xml version="1.0" encoding="UTF-8"?>\n
	b.WriteString(`<asic:XAdESSignatures xmlns:asic="`)
	b.WriteString(nsXAdESSignatures)
	b.WriteString(`">`)
	b.Write(ps.raw)
	b.WriteString(`</asic:XAdESSignatures>`)
	return b.Bytes(), nil
}

// collectSignatures parses every supplied signature file and flattens them into
// one parsedSignature per top-level ds:Signature, in input order. A single file
// holding multiple signatures yields multiple entries (each gets its own
// signatures*.xml on assembly).
func collectSignatures(signatures []File) ([]parsedSignature, error) {
	var all []parsedSignature
	for _, sf := range signatures {
		parsed, err := parseSignatures(sf.Data)
		if err != nil {
			return nil, fmt.Errorf("signature %q: %w", sf.Name, err)
		}
		all = append(all, parsed...)
	}
	if len(all) == 0 {
		return nil, ErrNoSignatures
	}
	return all, nil
}
