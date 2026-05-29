package asice

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"mime"
	"path"
	"strings"
)

// ManifestEntry is one file-entry in META-INF/manifest.xml.
type ManifestEntry struct {
	FullPath  string // manifest:full-path ("/" for the container root entry)
	MediaType string // manifest:media-type
}

// Manifest is the parsed META-INF/manifest.xml (OpenDocument-style), as used by
// .asice profile.
type Manifest struct {
	Entries []ManifestEntry
}

// buildManifest constructs the manifest for a set of data objects. The root file-entry media-type is always the ASiC-E media
// type, followed by one entry per data object with a per-file media type.
func buildManifest(docs []File) Manifest {
	entries := make([]ManifestEntry, 0, len(docs)+1)
	entries = append(entries, ManifestEntry{FullPath: "/", MediaType: MimeType})
	for _, d := range docs {
		entries = append(entries, ManifestEntry{
			FullPath:  d.Name,
			MediaType: mediaType(d.Name),
		})
	}
	return Manifest{Entries: entries}
}

// render serialises the manifest to XML bytes. The fixed shape is written
// directly so the conventional "manifest:" prefix is preserved exactly
// (encoding/xml does not give reliable control over output prefixes).
func (m Manifest) render() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(xml.Header) // <?xml version="1.0" encoding="UTF-8"?>\n
	b.WriteString(`<manifest:manifest xmlns:manifest="` + nsManifest + "\">\n")
	for _, e := range m.Entries {
		b.WriteString(`  <manifest:file-entry manifest:media-type="`)
		if err := xml.EscapeText(&b, []byte(e.MediaType)); err != nil {
			return nil, err
		}
		b.WriteString(`" manifest:full-path="`)
		if err := xml.EscapeText(&b, []byte(e.FullPath)); err != nil {
			return nil, err
		}
		b.WriteString("\"/>\n")
	}
	b.WriteString("</manifest:manifest>\n")
	return b.Bytes(), nil
}

// xmlManifest mirrors META-INF/manifest.xml for reading. Tags omit namespaces
// so attributes match by local name regardless of the (conventional) manifest:
// prefix.
type xmlManifest struct {
	XMLName xml.Name
	Entries []struct {
		MediaType string `xml:"media-type,attr"`
		FullPath  string `xml:"full-path,attr"`
	} `xml:"file-entry"`
}

// parseManifest reads a META-INF/manifest.xml.
func parseManifest(data []byte) (Manifest, error) {
	var xm xmlManifest
	if err := xml.Unmarshal(data, &xm); err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest.xml: %v", ErrInvalidContainer, err)
	}
	var m Manifest
	for _, fe := range xm.Entries {
		m.Entries = append(m.Entries, ManifestEntry{
			FullPath:  fe.FullPath,
			MediaType: fe.MediaType,
		})
	}
	return m, nil
}

// extraMediaTypes covers types commonly seen in signed documents that the Go
// mime database may not map on every platform (notably Windows registry-backed
// lookups). Container assembly stays robust regardless of host configuration.
var extraMediaTypes = map[string]string{
	".pdf":   "application/pdf",
	".xml":   "text/xml",
	".txt":   "text/plain",
	".csv":   "text/csv",
	".json":  "application/json",
	".html":  "text/html",
	".htm":   "text/html",
	".doc":   "application/msword",
	".docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls":   "application/vnd.ms-excel",
	".xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt":   "application/vnd.ms-powerpoint",
	".pptx":  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".odt":   "application/vnd.oasis.opendocument.text",
	".ods":   "application/vnd.oasis.opendocument.spreadsheet",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".tif":   "image/tiff",
	".tiff":  "image/tiff",
	".zip":   "application/zip",
	".asice": MimeType,
	".edoc":  MimeType,
}

// mediaType returns the media type for a data-object filename, falling back to
// application/octet-stream when unknown.
func mediaType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := extraMediaTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		// Drop any "; charset=..." parameter the mime db appends.
		if i := strings.IndexByte(t, ';'); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		return t
	}
	return "application/octet-stream"
}
