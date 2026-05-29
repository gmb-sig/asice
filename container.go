package asice

import (
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

// BuildContainer assembles a new ASiC-E container from one or more original
// documents and one or more XAdES signature files, returning the raw .asice
// bytes.
//
// Unless opts.SkipReferenceCheck is set, it first verifies (via CheckReferences)
// that the signatures reference exactly the supplied documents. The ZIP is laid
// out per ETSI EN 319 162-1: an uncompressed "mimetype" entry first, the
// documents in the container root, then META-INF/manifest.xml and one
// META-INF/signatures*.xml per signature.
func BuildContainer(docs, signatures []File, opts *BuildOptions) ([]byte, error) {
	if opts == nil {
		opts = &BuildOptions{}
	}
	if len(docs) == 0 {
		return nil, ErrNoDocuments
	}
	if len(signatures) == 0 {
		return nil, ErrNoSignatures
	}
	if !opts.SkipReferenceCheck {
		if err := CheckReferences(docs, signatures); err != nil {
			return nil, err
		}
	}
	sigs, err := collectSignatures(signatures)
	if err != nil {
		return nil, err
	}

	manifest, err := buildManifest(docs).render()
	if err != nil {
		return nil, fmt.Errorf("render manifest: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeMimetype(zw); err != nil {
		return nil, err
	}
	for _, d := range docs {
		if err := writeStoredFile(zw, d.Name, d.Data, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := writeStoredFile(zw, manifestPath, manifest, zip.Deflate); err != nil {
		return nil, err
	}
	for i, ps := range sigs {
		sigXML, err := wrapSignature(ps)
		if err != nil {
			return nil, err
		}
		if err := writeStoredFile(zw, signatureFileName(i), sigXML, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalise container: %w", err)
	}
	return buf.Bytes(), nil
}

// AddSignature adds a parallel (co-) signature to an existing ASiC-E container
// and returns a new container. The existing entries — data objects and prior
// signatures — are copied byte-for-byte so that previously valid signatures are
// never broken; the container is treated as immutable input.
//
// The new signature must reference the same data objects the container already
// holds (same filenames and digests), otherwise an error wrapping
// ErrSignatureTargetMismatch is returned. The next signatures*.xml index is
// derived internally — the caller never supplies it.
func AddSignature(container, newSignature []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}

	objects, names, err := readEntries(zr)
	if err != nil {
		return nil, err
	}

	// The new signature must target exactly the container's data objects.
	parsed, err := parseSignatures(newSignature)
	if err != nil {
		return nil, err
	}
	for _, ps := range parsed {
		if err := verifySignatureTargets(ps.refs, objects); err != nil {
			return nil, err
		}
	}

	index := nextSignatureIndex(names)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Copy every existing entry raw (compressed bytes + CRC preserved), keeping
	// original order so the mimetype stays first.
	for _, f := range zr.File {
		if err := copyRaw(zw, f); err != nil {
			return nil, err
		}
	}
	// Append the new signature(s); a multi-signature file becomes consecutive
	// signatures*.xml entries.
	for _, ps := range parsed {
		sigXML, err := wrapSignature(ps)
		if err != nil {
			return nil, err
		}
		if err := writeStoredFile(zw, signatureFileName(index), sigXML, zip.Deflate); err != nil {
			return nil, err
		}
		index++
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalise container: %w", err)
	}
	return buf.Bytes(), nil
}

// verifySignatureTargets checks that a new signature's references match the
// container's data objects exactly, returning errors wrapping
// ErrSignatureTargetMismatch.
func verifySignatureTargets(refs []Reference, objects []File) error {
	byName := make(map[string]File, len(objects))
	for _, o := range objects {
		byName[o.Name] = o
	}
	refNames := distinctNames(refs)
	if len(refNames) != len(byName) {
		return fmt.Errorf("%w: new signature references %d object(s), container holds %d (%v)",
			ErrSignatureTargetMismatch, len(refNames), len(byName), sortedNames(toSet(objects)))
	}
	for name := range refNames {
		if _, ok := byName[name]; !ok {
			return fmt.Errorf("%w: new signature references %q, not present in container",
				ErrSignatureTargetMismatch, name)
		}
	}
	for _, ref := range refs {
		obj := byName[ref.URI]
		got, err := digestBase64(ref.Algorithm, obj.Data)
		if err != nil {
			return err
		}
		if !digestEqual(got, ref.DigestValue) {
			return fmt.Errorf("%w: digest for %q differs from the container's data object",
				ErrSignatureTargetMismatch, ref.URI)
		}
	}
	return nil
}

func toSet(objects []File) map[string]bool {
	s := make(map[string]bool, len(objects))
	for _, o := range objects {
		s[o.Name] = true
	}
	return s
}

// readEntries reads a container's root-level data objects and returns their
// contents plus the full list of entry names (used for signature indexing).
func readEntries(zr *zip.Reader) (objects []File, names []string, err error) {
	for _, f := range zr.File {
		names = append(names, f.Name)
		if !isDataObject(f.Name) {
			continue
		}
		data, rerr := readZipFile(f)
		if rerr != nil {
			return nil, nil, rerr
		}
		objects = append(objects, File{Name: f.Name, Data: data})
	}
	return objects, names, nil
}

// isDataObject reports whether an entry is a container-root data object (not the
// mimetype, not anything under META-INF/, not a directory).
func isDataObject(name string) bool {
	if name == mimetypePath || strings.HasPrefix(name, metaInfDir) {
		return false
	}
	if strings.HasSuffix(name, "/") {
		return false
	}
	return true
}

// readZipFile reads a single entry, rejecting unsafe paths.
func readZipFile(f *zip.File) ([]byte, error) {
	if !safePath(f.Name) {
		return nil, fmt.Errorf("%w: unsafe entry path %q", ErrInvalidContainer, f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %v", ErrInvalidContainer, f.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("%w: read %q: %v", ErrInvalidContainer, f.Name, err)
	}
	return data, nil
}

// safePath rejects absolute paths and any path containing a ".." segment,
// guarding against path traversal when reading an untrusted container.
func safePath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return false
	}
	for _, seg := range strings.Split(strings.ReplaceAll(name, `\`, "/"), "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// writeMimetype writes the uncompressed "mimetype" entry as the first member of
// the ZIP, with a clean local header (no data descriptor) via CreateRaw, as
// required for ASiC-E.
func writeMimetype(zw *zip.Writer) error {
	content := []byte(MimeType)
	fh := &zip.FileHeader{Name: mimetypePath, Method: zip.Store}
	fh.CRC32 = crc32.ChecksumIEEE(content)
	fh.CompressedSize64 = uint64(len(content))
	fh.UncompressedSize64 = uint64(len(content))
	w, err := zw.CreateRaw(fh)
	if err != nil {
		return fmt.Errorf("write mimetype header: %w", err)
	}
	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("write mimetype: %w", err)
	}
	return nil
}

// writeStoredFile writes a normal entry with the given compression method.
func writeStoredFile(zw *zip.Writer, name string, data []byte, method uint16) error {
	fh := &zip.FileHeader{Name: name, Method: method}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		return fmt.Errorf("write %q header: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write %q: %w", name, err)
	}
	return nil
}

// copyRaw copies an existing entry into zw preserving its exact bytes, CRC, and
// compression, so signatures over it remain valid.
func copyRaw(zw *zip.Writer, f *zip.File) error {
	if !safePath(f.Name) {
		return fmt.Errorf("%w: unsafe entry path %q", ErrInvalidContainer, f.Name)
	}
	header := f.FileHeader
	// Clear the data-descriptor flag: CreateRaw writes CRC/sizes in the local
	// header itself, so a trailing descriptor must not be advertised.
	header.Flags &^= 0x08
	w, err := zw.CreateRaw(&header)
	if err != nil {
		return fmt.Errorf("copy %q header: %w", f.Name, err)
	}
	rc, err := f.OpenRaw()
	if err != nil {
		return fmt.Errorf("open raw %q: %w", f.Name, err)
	}
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("copy %q: %w", f.Name, err)
	}
	return nil
}
