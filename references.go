package asice

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// Reference is a single ds:Reference to an external data object, extracted from
// a XAdES signature's SignedInfo. Same-document references (URIs beginning with
// "#", e.g. the SignedProperties or KeyInfo references) are not data objects and
// are excluded.
type Reference struct {
	URI         string // decoded data-object filename (container-relative)
	Algorithm   string // ds:DigestMethod Algorithm URI
	DigestValue string // ds:DigestValue, base64 as recorded in the signature
}

// parsedSignature is a top-level ds:Signature found in a signature file. raw is
// the verbatim, namespace-complete <ds:Signature>...</ds:Signature> byte span,
// ready to embed unchanged inside a XAdESSignatures wrapper — preserving the
// signed bytes exactly. refs are the data-object references it covers.
type parsedSignature struct {
	raw  []byte
	refs []Reference
}

// nsFrame records the namespace declarations on one element while we walk the
// document, so a signature lifted out of it keeps its in-scope namespaces.
type nsFrame struct {
	decls map[string]string // prefix -> URI ("" == default namespace)
	isSig bool              // this element is a top-level ds:Signature
}

// parseSignatures reads a XAdES signature file and returns every top-level
// ds:Signature it contains, captured verbatim. A "top-level" signature is one
// not nested inside another ds:Signature (which would be a countersignature —
// out of scope). The input may be a bare ds:Signature, a XAdESSignatures
// wrapper, or any tree that contains them.
//
// It uses a streaming decoder only to locate signature byte-spans and track
// namespace scope; the signature bytes themselves are never re-serialised, so
// the canonicalised SignedInfo the signature covers is preserved exactly.
func parseSignatures(data []byte) ([]parsedSignature, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	// Tolerate declared non-UTF-8 charsets by passing bytes through unchanged;
	// XAdES is UTF-8 in practice and the data we read (URIs, base64 digests) is
	// ASCII regardless.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }

	var (
		out         []parsedSignature
		stack       []nsFrame
		startOfNext int64

		capturing bool
		sigDepth  = -1
		sigStart  int64
		inherited map[string]string
		sigOwn    map[string]string
	)

	for {
		tokStart := startOfNext
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedXAdES, err)
		}
		tokEnd := dec.InputOffset()
		startOfNext = tokEnd

		switch t := tok.(type) {
		case xml.StartElement:
			decls := collectDecls(t)
			isSig := t.Name.Local == "Signature" && t.Name.Space == nsDSig
			if isSig && !capturing {
				capturing = true
				sigDepth = len(stack)
				sigStart = tokStart
				sigOwn = decls
				inherited = flattenScope(stack)
			}
			stack = append(stack, nsFrame{decls: decls, isSig: isSig})

		case xml.EndElement:
			top := len(stack) - 1
			popped := stack[top]
			stack = stack[:top]
			if capturing && top == sigDepth && popped.isSig {
				raw := data[sigStart:tokEnd]
				if k := bytes.IndexByte(raw, '<'); k > 0 {
					raw = raw[k:] // drop any whitespace before the start tag
				}
				raw = injectNamespaces(raw, inherited, sigOwn)
				refs, err := extractReferences(raw)
				if err != nil {
					return nil, err
				}
				out = append(out, parsedSignature{raw: raw, refs: refs})
				capturing = false
				sigDepth = -1
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no ds:Signature element found", ErrMalformedXAdES)
	}
	return out, nil
}

// collectDecls returns the namespace declarations (xmlns / xmlns:*) on a start
// element.
func collectDecls(t xml.StartElement) map[string]string {
	var m map[string]string
	for _, a := range t.Attr {
		var prefix string
		switch {
		case a.Name.Space == "xmlns":
			prefix = a.Name.Local // xmlns:prefix
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			prefix = "" // default namespace
		default:
			continue
		}
		if m == nil {
			m = make(map[string]string)
		}
		m[prefix] = a.Value
	}
	return m
}

// flattenScope merges the namespace declarations of an ancestor chain (root ->
// parent) into a single prefix->URI map, with nearer declarations overriding.
func flattenScope(stack []nsFrame) map[string]string {
	scope := make(map[string]string)
	for _, f := range stack {
		for p, u := range f.decls {
			scope[p] = u
		}
	}
	return scope
}

// injectNamespaces adds the namespace declarations a signature relied on in its
// original document but that its new XAdESSignatures wrapper does not provide,
// so its namespace context survives being re-wrapped. The signature bytes are
// otherwise untouched. (For exclusive-C14N signatures — the XAdES norm —
// unused declarations are invisible to the canonical form anyway; this handles
// the inclusive case and keeps the element well-formed.)
func injectNamespaces(raw []byte, inherited, own map[string]string) []byte {
	provided := map[string]string{"asic": nsXAdESSignatures} // our wrapper declares this

	var add []string
	for p, u := range inherited {
		if _, redeclared := own[p]; redeclared {
			continue
		}
		if provided[p] == u {
			continue
		}
		add = append(add, p)
	}
	if len(add) == 0 {
		return raw
	}
	sort.Strings(add)

	var ins bytes.Buffer
	for _, p := range add {
		ins.WriteByte(' ')
		if p == "" {
			ins.WriteString(`xmlns="`)
		} else {
			ins.WriteString("xmlns:" + p + `="`)
		}
		xml.EscapeText(&ins, []byte(inherited[p]))
		ins.WriteByte('"')
	}

	// Insert right after the start-tag element name.
	i := 1 // raw[0] == '<'
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\n', '\r', '>', '/':
			out := make([]byte, 0, len(raw)+ins.Len())
			out = append(out, raw[:i]...)
			out = append(out, ins.Bytes()...)
			return append(out, raw[i:]...)
		}
		i++
	}
	return raw
}

// xmlReference / xmlSignature mirror just enough of a ds:Signature to read its
// SignedInfo references. Tags omit namespaces so matching is by local name,
// regardless of the prefix (ds, dsig, default) the signer used.
type xmlReference struct {
	URI          string `xml:"URI,attr"`
	Type         string `xml:"Type,attr"`
	DigestMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	} `xml:"DigestMethod"`
	DigestValue string `xml:"DigestValue"`
}

type xmlSignature struct {
	XMLName    xml.Name
	References []xmlReference `xml:"SignedInfo>Reference"`
}

// extractReferences returns the external data-object references of a single
// ds:Signature (those in SignedInfo whose URI is not a same-document fragment).
func extractReferences(rawSig []byte) ([]Reference, error) {
	var sig xmlSignature
	if err := xml.Unmarshal(rawSig, &sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedXAdES, err)
	}
	var refs []Reference
	for _, r := range sig.References {
		// Same-document references (SignedProperties, KeyInfo, ...) start with
		// "#" or are empty; they are not data objects.
		if r.URI == "" || strings.HasPrefix(r.URI, "#") {
			continue
		}
		refs = append(refs, Reference{
			URI:         decodeURI(r.URI),
			Algorithm:   r.DigestMethod.Algorithm,
			DigestValue: strings.TrimSpace(r.DigestValue),
		})
	}
	return refs, nil
}

// decodeURI turns a ds:Reference URI into a container-relative filename:
// percent-decoded, with any leading "./" stripped.
func decodeURI(uri string) string {
	if dec, err := url.PathUnescape(uri); err == nil {
		uri = dec
	}
	return strings.TrimPrefix(uri, "./")
}

// CheckReferences verifies that every supplied signature references exactly the
// supplied documents: same count, same filenames, and a matching digest for
// each document (pillar 6.1). It performs no cryptographic signature
// verification — only hashing and XML reading.
//
// On mismatch it returns an error wrapping one of ErrFileCountMismatch,
// ErrFilenameMismatch, or ErrDigestMismatch (or ErrMalformedXAdES /
// ErrUnsupportedDigest while parsing).
func CheckReferences(docs, signatures []File) error {
	if len(docs) == 0 {
		return ErrNoDocuments
	}
	if len(signatures) == 0 {
		return ErrNoSignatures
	}

	byName := make(map[string]File, len(docs))
	for _, d := range docs {
		byName[d.Name] = d
	}

	for _, sf := range signatures {
		parsed, err := parseSignatures(sf.Data)
		if err != nil {
			return fmt.Errorf("signature %q: %w", sf.Name, err)
		}
		for _, ps := range parsed {
			if err := checkSignatureRefs(sf.Name, ps.refs, byName); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkSignatureRefs compares one signature's data-object references against the
// provided documents.
func checkSignatureRefs(sigName string, refs []Reference, byName map[string]File) error {
	// Count: distinct referenced names vs distinct provided names.
	refNames := distinctNames(refs)
	if len(refNames) != len(byName) {
		return fmt.Errorf("%w: signature %q references %d data object(s), %d document(s) provided",
			ErrFileCountMismatch, sigName, len(refNames), len(byName))
	}

	// Filenames: every reference must name a provided document, and vice versa.
	for name := range refNames {
		if _, ok := byName[name]; !ok {
			return fmt.Errorf("%w: signature %q references %q, which was not provided",
				ErrFilenameMismatch, sigName, name)
		}
	}
	for name := range byName {
		if !refNames[name] {
			return fmt.Errorf("%w: document %q is not referenced by signature %q",
				ErrFilenameMismatch, name, sigName)
		}
	}

	// Digests: each reference's recorded digest must match the document bytes.
	for _, ref := range refs {
		doc := byName[ref.URI]
		got, err := digestBase64(ref.Algorithm, doc.Data)
		if err != nil {
			return fmt.Errorf("signature %q, reference %q: %w", sigName, ref.URI, err)
		}
		if !digestEqual(got, ref.DigestValue) {
			return fmt.Errorf("%w: document %q does not match the digest in signature %q",
				ErrDigestMismatch, ref.URI, sigName)
		}
	}
	return nil
}

// distinctNames returns the set of referenced data-object names.
func distinctNames(refs []Reference) map[string]bool {
	set := make(map[string]bool, len(refs))
	for _, r := range refs {
		set[r.URI] = true
	}
	return set
}

// digestEqual compares two base64 digest strings, tolerating differences in
// internal whitespace (some signers wrap DigestValue across lines).
func digestEqual(a, b string) bool {
	return stripSpace(a) == stripSpace(b)
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// sortedNames returns the keys of a name set, sorted — used for deterministic
// output and error messages.
func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
