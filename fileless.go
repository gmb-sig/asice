package asice

import (
	"archive/zip"
	"bytes"
	"fmt"
)

// ExtractSignatures returns the signatures*.xml entries from a container,
// including a fileless one. The returned File.Data is suitable to pass to
// AddSignature.
func ExtractSignatures(container []byte) ([]File, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}

	var sigs []File
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, File{Name: f.Name, Data: data})
	}

	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}
	return sigs, nil
}

// AddDocuments inserts data object(s) into a container that references them but
// is missing their bytes (e.g. a hash-signed, fileless container), producing a
// complete .asice. It verifies that each supplied document matches what the
// container's signatures reference before inserting.
func AddDocuments(container []byte, docs []File) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}

	// Collect all data-object references from every signature in the container.
	refsByName := make(map[string]Reference)
	hasSignatures := false
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		hasSignatures = true
		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}
		parsed, err := parseSignatures(data)
		if err != nil {
			return nil, err
		}
		for _, ps := range parsed {
			for _, ref := range ps.refs {
				refsByName[ref.URI] = ref
			}
		}
	}
	if !hasSignatures {
		return nil, ErrNoSignatures
	}

	// Names of data objects already present in the container.
	presentObjects := make(map[string]bool)
	for _, f := range zr.File {
		if isDataObject(f.Name) {
			presentObjects[f.Name] = true
		}
	}

	// Validate each supplied doc: must be referenced, not already present, and
	// its digest must match what the signature recorded.
	for _, doc := range docs {
		ref, ok := refsByName[doc.Name]
		if !ok {
			return nil, fmt.Errorf("%w: %q is not referenced by any signature in the container",
				ErrFilenameMismatch, doc.Name)
		}
		if presentObjects[doc.Name] {
			return nil, fmt.Errorf("%w: %q is already present in the container",
				ErrFilenameMismatch, doc.Name)
		}
		got, err := digestBase64(ref.Algorithm, doc.Data)
		if err != nil {
			return nil, fmt.Errorf("document %q: %w", doc.Name, err)
		}
		if !digestEqual(got, ref.DigestValue) {
			return nil, fmt.Errorf("%w: document %q", ErrDigestMismatch, doc.Name)
		}
	}

	// After processing, every referenced object must be present (already in the
	// container or among the supplied docs).
	docsByName := make(map[string]bool)
	for _, d := range docs {
		docsByName[d.Name] = true
	}
	for name := range refsByName {
		if !presentObjects[name] && !docsByName[name] {
			return nil, fmt.Errorf("%w: referenced object %q not provided",
				ErrFilenameMismatch, name)
		}
	}

	// Parse the existing manifest so we can supplement it with entries for the
	// new docs (a fileless manifest usually already names them; add only if absent).
	var existingManifest Manifest
	for _, f := range zr.File {
		if f.Name != manifestPath {
			continue
		}
		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}
		existingManifest, err = parseManifest(data)
		if err != nil {
			return nil, err
		}
		break
	}
	manifestByPath := make(map[string]bool)
	for _, e := range existingManifest.Entries {
		manifestByPath[e.FullPath] = true
	}
	updatedManifest := existingManifest
	for _, doc := range docs {
		if !manifestByPath[doc.Name] {
			updatedManifest.Entries = append(updatedManifest.Entries, ManifestEntry{
				FullPath:  doc.Name,
				MediaType: mediaType(doc.Name),
			})
		}
	}
	manifestXML, err := updatedManifest.render()
	if err != nil {
		return nil, fmt.Errorf("render manifest: %w", err)
	}

	// Assemble the new container: mimetype first (raw), then new docs, then the
	// updated manifest, then all signature files (raw so they remain valid).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, f := range zr.File {
		if f.Name == mimetypePath {
			if err := copyRaw(zw, f); err != nil {
				return nil, err
			}
			break
		}
	}
	for _, doc := range docs {
		if err := writeStoredFile(zw, doc.Name, doc.Data, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := writeStoredFile(zw, manifestPath, manifestXML, zip.Deflate); err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		if err := copyRaw(zw, f); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalise container: %w", err)
	}
	return buf.Bytes(), nil
}
