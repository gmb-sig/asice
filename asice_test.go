package asice

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// --- test fixtures -----------------------------------------------------------

func sha256b64(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// xadesOpts controls how the synthetic XAdES fixture is shaped.
type xadesOpts struct {
	id          string // ds:Signature Id
	nsOnWrapper bool   // declare xmlns:ds on a wrapper instead of the Signature
	wrongDigest bool   // emit a corrupted digest for the first reference
}

// makeXAdES builds a minimal-but-realistic detached XAdES signature file that
// references the given documents (correct SHA-256 digests) plus a
// SignedProperties fragment reference that must be ignored as a data object.
func makeXAdES(t *testing.T, docs []File, o xadesOpts) []byte {
	t.Helper()
	dsNS := `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	wrapperOpen, wrapperClose := "", ""
	sigNS := dsNS
	if o.nsOnWrapper {
		// Move the ds namespace declaration up to a wrapper so the Signature
		// element inherits it — exercises inheritNamespaces.
		wrapperOpen = fmt.Sprintf(`<asic:XAdESSignatures xmlns:asic="%s" %s>`, nsXAdESSignatures, dsNS)
		wrapperClose = `</asic:XAdESSignatures>`
		sigNS = ""
	}

	var refs strings.Builder
	for i, d := range docs {
		dv := sha256b64(d.Data)
		if o.wrongDigest && i == 0 {
			dv = base64.StdEncoding.EncodeToString([]byte("not the real digest!"))
		}
		fmt.Fprintf(&refs, `<ds:Reference Id="r%d" URI="%s">`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`, i, d.Name, dv)
	}

	id := o.id
	if id == "" {
		id = "S0"
	}
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`%s<ds:Signature %s Id="%s"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>`+
		`%s`+
		`<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp-%s">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
		`</ds:SignedInfo>`+
		`<ds:SignatureValue>Zm9v</ds:SignatureValue>`+
		`</ds:Signature>%s`,
		wrapperOpen, sigNS, id, refs.String(), id, sha256b64([]byte("props")), wrapperClose)
	return []byte(xml)
}

func sampleDocs() []File {
	return []File{
		{Name: "doc1.txt", Data: []byte("hello world")},
		{Name: "report.pdf", Data: []byte("%PDF-1.4 fake pdf bytes")},
	}
}

func readZipEntry(t *testing.T, container []byte, name string) ([]byte, *zip.File) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatalf("open container: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open %q: %v", name, err)
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read %q: %v", name, err)
			}
			return data, f
		}
	}
	t.Fatalf("entry %q not found", name)
	return nil, nil
}

// --- CheckReferences ---------------------------------------------------------

func TestCheckReferences_OK(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	if err := CheckReferences(docs, []File{sig}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestCheckReferences_Errors(t *testing.T) {
	docs := sampleDocs()

	t.Run("count mismatch", func(t *testing.T) {
		sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
		// Provide only one of the two referenced docs.
		err := CheckReferences(docs[:1], []File{sig})
		if !errors.Is(err, ErrFileCountMismatch) {
			t.Fatalf("want ErrFileCountMismatch, got %v", err)
		}
	})

	t.Run("filename mismatch", func(t *testing.T) {
		sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
		renamed := []File{docs[0], {Name: "other.pdf", Data: docs[1].Data}}
		err := CheckReferences(renamed, []File{sig})
		if !errors.Is(err, ErrFilenameMismatch) {
			t.Fatalf("want ErrFilenameMismatch, got %v", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{wrongDigest: true})}
		err := CheckReferences(docs, []File{sig})
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("want ErrDigestMismatch, got %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		sig := File{Name: "xades.xml", Data: []byte("not xml at all <<<")}
		err := CheckReferences(docs, []File{sig})
		if !errors.Is(err, ErrMalformedXAdES) {
			t.Fatalf("want ErrMalformedXAdES, got %v", err)
		}
	})

	t.Run("no documents", func(t *testing.T) {
		if err := CheckReferences(nil, []File{{Name: "x", Data: []byte("x")}}); !errors.Is(err, ErrNoDocuments) {
			t.Fatalf("want ErrNoDocuments, got %v", err)
		}
	})
}

// --- BuildContainer ----------------------------------------------------------

func TestBuildContainer_Layout(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}

	container, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	// mimetype must be the first entry, stored, with the right magic layout and
	// no data descriptor flag (offset reference: ETSI EN 319 162-1).
	if got := string(container[0:4]); got != "PK\x03\x04" {
		t.Fatalf("missing local file header magic, got %q", got)
	}
	flag := uint16(container[6]) | uint16(container[7])<<8
	if flag&0x08 != 0 {
		t.Fatalf("mimetype entry must not use a data descriptor (flag=%#x)", flag)
	}
	method := uint16(container[8]) | uint16(container[9])<<8
	if method != zip.Store {
		t.Fatalf("mimetype must be stored (method=%d)", method)
	}
	if got := string(container[30:38]); got != "mimetype" {
		t.Fatalf("first entry name = %q, want mimetype", got)
	}
	if got := string(container[38 : 38+len(MimeType)]); got != MimeType {
		t.Fatalf("mimetype content = %q, want %q", got, MimeType)
	}

	// Entry order: mimetype first.
	zr, _ := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if zr.File[0].Name != mimetypePath {
		t.Fatalf("first zip entry = %q, want mimetype", zr.File[0].Name)
	}

	// Required members present.
	for _, name := range []string{mimetypePath, manifestPath, "doc1.txt", "report.pdf", "META-INF/signatures0.xml"} {
		readZipEntry(t, container, name) // fatals if missing / bad CRC
	}

	// Documents stored byte-identical.
	got, _ := readZipEntry(t, container, "doc1.txt")
	if !bytes.Equal(got, docs[0].Data) {
		t.Fatalf("doc1.txt content altered")
	}
}

func TestBuildContainer_ManifestAndSignature(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	container, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	manifest, sigs, objs, err := Inspect(container)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// Manifest: root entry first with the ASiC media type, then one per doc.
	if len(manifest.Entries) != 3 {
		t.Fatalf("manifest entries = %d, want 3", len(manifest.Entries))
	}
	if manifest.Entries[0].FullPath != "/" || manifest.Entries[0].MediaType != MimeType {
		t.Fatalf("manifest root entry wrong: %+v", manifest.Entries[0])
	}
	wantTypes := map[string]string{"doc1.txt": "text/plain", "report.pdf": "application/pdf"}
	for _, e := range manifest.Entries[1:] {
		if wantTypes[e.FullPath] != e.MediaType {
			t.Fatalf("manifest entry %q media-type = %q, want %q", e.FullPath, e.MediaType, wantTypes[e.FullPath])
		}
	}

	if len(sigs) != 1 {
		t.Fatalf("signatures = %d, want 1", len(sigs))
	}
	if sigs[0].Path != "META-INF/signatures0.xml" {
		t.Fatalf("signature path = %q", sigs[0].Path)
	}
	if len(sigs[0].References) != 2 {
		t.Fatalf("data-object references = %d, want 2", len(sigs[0].References))
	}
	if len(objs) != 2 {
		t.Fatalf("data objects = %d, want 2", len(objs))
	}
}

func TestBuildContainer_MultipleSignatures(t *testing.T) {
	docs := sampleDocs()
	s0 := File{Name: "a.xml", Data: makeXAdES(t, docs, xadesOpts{id: "A"})}
	s1 := File{Name: "b.xml", Data: makeXAdES(t, docs, xadesOpts{id: "B"})}
	container, err := BuildContainer(docs, []File{s0, s1}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	readZipEntry(t, container, "META-INF/signatures0.xml")
	readZipEntry(t, container, "META-INF/signatures1.xml")
}

func TestBuildContainer_NamespaceInheritance(t *testing.T) {
	docs := sampleDocs()
	// ds namespace lives on the wrapper, not the Signature element.
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{nsOnWrapper: true})}
	container, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	sigXML, _ := readZipEntry(t, container, "META-INF/signatures0.xml")

	// The lifted Signature element must now carry the ds declaration in its own
	// start tag (it was declared on the wrapper in the input).
	start := bytes.Index(sigXML, []byte("<ds:Signature"))
	if start < 0 {
		t.Fatalf("ds:Signature element not found in output:\n%s", sigXML)
	}
	rel := bytes.IndexByte(sigXML[start:], '>')
	if rel < 0 {
		t.Fatalf("unterminated Signature start tag")
	}
	startTag := string(sigXML[start : start+rel+1])
	if !strings.Contains(startTag, `xmlns:ds="`+nsDSig+`"`) {
		t.Fatalf("ds namespace not inherited onto Signature element; start tag = %s", startTag)
	}
	// And it must still be parseable with its references intact.
	if _, _, sigs := mustInspect(t, container); len(sigs[0].References) != 2 {
		t.Fatalf("references lost after wrapping")
	}
}

func mustInspect(t *testing.T, container []byte) (Manifest, []DataObject, []SignatureInfo) {
	t.Helper()
	m, s, o, err := Inspect(container)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return m, o, s
}

// --- AddSignature ------------------------------------------------------------

func TestAddSignature(t *testing.T) {
	docs := sampleDocs()
	first := File{Name: "first.xml", Data: makeXAdES(t, docs, xadesOpts{id: "FIRST"})}
	container, err := BuildContainer(docs, []File{first}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	orig0, _ := readZipEntry(t, container, "META-INF/signatures0.xml")
	origDoc1, _ := readZipEntry(t, container, "doc1.txt")

	second := makeXAdES(t, docs, xadesOpts{id: "SECOND"})
	updated, err := AddSignature(container, second)
	if err != nil {
		t.Fatalf("AddSignature: %v", err)
	}

	// New signature lands at the next free index.
	readZipEntry(t, updated, "META-INF/signatures1.xml")

	// Existing entries are byte-identical (so prior signatures stay valid).
	new0, _ := readZipEntry(t, updated, "META-INF/signatures0.xml")
	if !bytes.Equal(orig0, new0) {
		t.Fatalf("existing signature0 changed after AddSignature")
	}
	newDoc1, _ := readZipEntry(t, updated, "doc1.txt")
	if !bytes.Equal(origDoc1, newDoc1) {
		t.Fatalf("data object changed after AddSignature")
	}

	_, sigs, _, err := Inspect(updated)
	if err != nil {
		t.Fatalf("Inspect updated: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("signatures after add = %d, want 2", len(sigs))
	}
}

func TestAddSignature_TargetMismatch(t *testing.T) {
	docs := sampleDocs()
	first := File{Name: "first.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	container, err := BuildContainer(docs, []File{first}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	// A signature over a different set of documents.
	otherDocs := []File{{Name: "doc1.txt", Data: []byte("hello world")}, {Name: "extra.txt", Data: []byte("xxx")}}
	bad := makeXAdES(t, otherDocs, xadesOpts{})
	if _, err := AddSignature(container, bad); !errors.Is(err, ErrSignatureTargetMismatch) {
		t.Fatalf("want ErrSignatureTargetMismatch, got %v", err)
	}
}

// --- unit helpers ------------------------------------------------------------

func TestNextSignatureIndex(t *testing.T) {
	cases := []struct {
		names []string
		want  int
	}{
		{nil, 0},
		{[]string{"mimetype", "META-INF/manifest.xml"}, 0},
		{[]string{"META-INF/signatures0.xml"}, 1},
		{[]string{"META-INF/signatures0.xml", "META-INF/signatures1.xml"}, 2},
		{[]string{"META-INF/signatures.xml"}, 1}, // bare name == index 0
		{[]string{"META-INF/signatures5.xml", "META-INF/signatures2.xml"}, 6},
	}
	for _, c := range cases {
		if got := nextSignatureIndex(c.names); got != c.want {
			t.Errorf("nextSignatureIndex(%v) = %d, want %d", c.names, got, c.want)
		}
	}
}

func TestMediaType(t *testing.T) {
	cases := map[string]string{
		"a.pdf":     "application/pdf",
		"b.TXT":     "text/plain",
		"c.unknown": "application/octet-stream",
		"d.docx":    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}
	for name, want := range cases {
		if got := mediaType(name); got != want {
			t.Errorf("mediaType(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSafePath(t *testing.T) {
	bad := []string{"", "/etc/passwd", "../escape", "a/../../b", `..\windows`}
	for _, p := range bad {
		if safePath(p) {
			t.Errorf("safePath(%q) = true, want false", p)
		}
	}
	for _, p := range []string{"doc.pdf", "META-INF/signatures0.xml", "sub/dir/file.txt"} {
		if !safePath(p) {
			t.Errorf("safePath(%q) = false, want true", p)
		}
	}
}

// --- ExtractSignatures / AddDocuments (fileless containers) ------------------

// makeFileless strips the data objects from a complete container, producing a
// fileless one as if the signing service never had the file bytes.
func makeFileless(t *testing.T, full []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(full), int64(len(full)))
	if err != nil {
		t.Fatalf("makeFileless: open zip: %v", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if isDataObject(f.Name) {
			continue
		}
		if err := copyRaw(zw, f); err != nil {
			t.Fatalf("makeFileless: copy %q: %v", f.Name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("makeFileless: close: %v", err)
	}
	return buf.Bytes()
}

func TestAddDocuments_Complete(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	full, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	fileless := makeFileless(t, full)

	completed, err := AddDocuments(fileless, docs)
	if err != nil {
		t.Fatalf("AddDocuments: %v", err)
	}

	// Data objects are present and byte-identical to the originals.
	for _, doc := range docs {
		got, _ := readZipEntry(t, completed, doc.Name)
		if !bytes.Equal(got, doc.Data) {
			t.Fatalf("%q content differs after AddDocuments", doc.Name)
		}
	}

	// Container parses correctly with the right counts.
	_, sigs, objs, err := Inspect(completed)
	if err != nil {
		t.Fatalf("Inspect completed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("signatures = %d, want 1", len(sigs))
	}
	if len(objs) != 2 {
		t.Fatalf("data objects = %d, want 2", len(objs))
	}
}

func TestAddDocuments_Errors(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	full, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	fileless := makeFileless(t, full)

	t.Run("wrong digest", func(t *testing.T) {
		badDoc := File{Name: docs[0].Name, Data: []byte("tampered content")}
		_, err := AddDocuments(fileless, []File{badDoc, docs[1]})
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("want ErrDigestMismatch, got %v", err)
		}
	})

	t.Run("wrong name", func(t *testing.T) {
		wrongName := File{Name: "other.txt", Data: docs[0].Data}
		_, err := AddDocuments(fileless, []File{wrongName, docs[1]})
		if !errors.Is(err, ErrFilenameMismatch) {
			t.Fatalf("want ErrFilenameMismatch, got %v", err)
		}
	})

	t.Run("incomplete — one doc missing", func(t *testing.T) {
		// Provide only one of the two referenced documents.
		_, err := AddDocuments(fileless, docs[:1])
		if !errors.Is(err, ErrFilenameMismatch) {
			t.Fatalf("want ErrFilenameMismatch (incomplete), got %v", err)
		}
	})

	t.Run("no signatures", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		writeMimetype(zw)
		zw.Close()
		_, err := AddDocuments(buf.Bytes(), docs)
		if !errors.Is(err, ErrNoSignatures) {
			t.Fatalf("want ErrNoSignatures, got %v", err)
		}
	})
}

func TestExtractSignatures_Basic(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	full, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}
	fileless := makeFileless(t, full)

	extracted, err := ExtractSignatures(fileless)
	if err != nil {
		t.Fatalf("ExtractSignatures: %v", err)
	}
	if len(extracted) != 1 {
		t.Fatalf("extracted %d signatures, want 1", len(extracted))
	}
	if extracted[0].Name != "META-INF/signatures0.xml" {
		t.Fatalf("Name = %q, want META-INF/signatures0.xml", extracted[0].Name)
	}
}

func TestExtractSignatures_NoSignatures(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeMimetype(zw)
	zw.Close()
	_, err := ExtractSignatures(buf.Bytes())
	if !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("want ErrNoSignatures, got %v", err)
	}
}

func TestExtractSignatures_InvalidContainer(t *testing.T) {
	_, err := ExtractSignatures([]byte("not a zip"))
	if !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("want ErrInvalidContainer, got %v", err)
	}
}

func TestExtractAndMerge(t *testing.T) {
	docs := sampleDocs()

	// First party: build a complete container.
	target, err := BuildContainer(docs, []File{{Name: "first.xml", Data: makeXAdES(t, docs, xadesOpts{id: "FIRST"})}}, nil)
	if err != nil {
		t.Fatalf("BuildContainer target: %v", err)
	}

	// Second party: co-signs the same docs; signing service produces a fileless container.
	secondFull, err := BuildContainer(docs, []File{{Name: "second.xml", Data: makeXAdES(t, docs, xadesOpts{id: "SECOND"})}}, nil)
	if err != nil {
		t.Fatalf("BuildContainer second: %v", err)
	}
	fileless := makeFileless(t, secondFull)

	// Extract the co-signature and merge it into the target.
	extracted, err := ExtractSignatures(fileless)
	if err != nil {
		t.Fatalf("ExtractSignatures: %v", err)
	}
	merged, err := AddSignature(target, extracted[0].Data)
	if err != nil {
		t.Fatalf("AddSignature: %v", err)
	}

	_, sigs, _, err := Inspect(merged)
	if err != nil {
		t.Fatalf("Inspect merged: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("merged signatures = %d, want 2", len(sigs))
	}
}

func TestExtractAndMerge_TargetMismatch(t *testing.T) {
	docs := sampleDocs()
	target, err := BuildContainer(docs, []File{{Name: "sig.xml", Data: makeXAdES(t, docs, xadesOpts{})}}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	// A second party that signed a different set of docs — name differs.
	otherDocs := []File{
		{Name: "doc1.txt", Data: []byte("hello world")},
		{Name: "extra.txt", Data: []byte("extra file content")},
	}
	secondFull, err := BuildContainer(otherDocs, []File{{Name: "sig2.xml", Data: makeXAdES(t, otherDocs, xadesOpts{})}}, nil)
	if err != nil {
		t.Fatalf("BuildContainer otherDocs: %v", err)
	}
	fileless := makeFileless(t, secondFull)

	extracted, err := ExtractSignatures(fileless)
	if err != nil {
		t.Fatalf("ExtractSignatures: %v", err)
	}
	if _, err := AddSignature(target, extracted[0].Data); !errors.Is(err, ErrSignatureTargetMismatch) {
		t.Fatalf("want ErrSignatureTargetMismatch, got %v", err)
	}
}

func TestAddDocuments_RoundTrip(t *testing.T) {
	docs := sampleDocs()
	sig := File{Name: "xades.xml", Data: makeXAdES(t, docs, xadesOpts{})}
	original, err := BuildContainer(docs, []File{sig}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	origSig0, _ := readZipEntry(t, original, "META-INF/signatures0.xml")

	fileless := makeFileless(t, original)
	completed, err := AddDocuments(fileless, docs)
	if err != nil {
		t.Fatalf("AddDocuments: %v", err)
	}

	// Data objects match the originals byte-for-byte.
	for _, doc := range docs {
		got, _ := readZipEntry(t, completed, doc.Name)
		if !bytes.Equal(got, doc.Data) {
			t.Fatalf("round-trip: %q content differs", doc.Name)
		}
	}

	// Signature is byte-for-byte unchanged (so it remains valid).
	newSig0, _ := readZipEntry(t, completed, "META-INF/signatures0.xml")
	if !bytes.Equal(origSig0, newSig0) {
		t.Fatalf("round-trip: signatures0.xml was modified by AddDocuments")
	}
}
