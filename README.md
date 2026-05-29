# asice

A small, framework-agnostic Go library for assembling and inspecting **ASiC-E**
(`.asice`) containers that hold **XAdES** signatures, per
[ETSI EN 319 162-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.00_30/en_31916201v010100v.pdf)
(ASiC) and ETSI EN 319 132-1 (XAdES).

```
go get github.com/gmb-sig/asice
```

It is the reusable packaging core. By design it does **no network I/O, no authentication, no
HTTP**, and performs **no cryptographic signature verification** — that SHALL BE
delegated to an external validator (example: `EU DSS`). The only checks here are
over **file digests and XAdES references** (hashing + XML reading), which keeps
the dependency surface to the standard library.

## API

| Function | Purpose |
|---|---|
| `BuildContainer(docs, signatures, opts) ([]byte, error)` | Assemble a new `.asice` from 1..N documents + 1..N XAdES signatures. |
| `AddSignature(container, newSignature) ([]byte, error)` | Add a parallel (co-) signature to an existing `.asice`; derives the next `signatures*.xml` index itself. |
| `Inspect(container) (Manifest, []SignatureInfo, []DataObject, error)` | Enumerate manifest, signatures, and data objects. |
| `CheckReferences(docs, signatures) error` | Verify signatures reference exactly the supplied documents (count + filename + SHA-2 digest). |

### Example

```go
docs := []asice.File{
    {Name: "contract.pdf", Data: pdfBytes},
}
sigs := []asice.File{
    {Name: "xades.xml", Data: xadesBytes}, // detached XAdES from CSC / wallet
}

// Optional: validate references explicitly (BuildContainer also does this
// unless BuildOptions.SkipReferenceCheck is set).
if err := asice.CheckReferences(docs, sigs); err != nil {
    log.Fatal(err)
}

container, err := asice.BuildContainer(docs, sigs, nil)
if err != nil {
    log.Fatal(err)
}
// `container` is the raw .asice — hand it to external validation service to validate.

// Later, a second party co-signs the same data objects:
updated, err := asice.AddSignature(container, secondXadesBytes)
```

## What it produces

A standards-shaped ASiC-E ZIP:

- `mimetype` — **first entry, stored uncompressed**, value
  `application/vnd.etsi.asic-e+zip`, written with a clean local header (no data
  descriptor) so it can be read as the container's leading bytes.
- the original document(s) in the container root.
- `META-INF/manifest.xml` — OpenDocument-style manifest; root file-entry
  media-type is always the ASiC-E type, then one entry per data object.
- `META-INF/signatures0.xml`, `signatures1.xml`, … — each a `XAdESSignatures`
  wrapper around one detached `ds:Signature`. (No `ASiCManifest.xml`: for the
  XAdES profile the per-file references live inside the signature.)

`AddSignature` copies all existing entries **byte-for-byte** (preserving
compressed bytes and CRC) and only appends a new signature file, so previously
valid signatures are never disturbed. The input container is treated as
immutable.

### National profile: validated-by-construction

The library does not hand-tune profile specifics beyond the manifest rule above.
A container is considered conformant once it passes validation through external validation service, `EU DSS` for example. 

## Errors

Mismatches return sentinel errors (use `errors.Is`):

`ErrFileCountMismatch`, `ErrFilenameMismatch`, `ErrDigestMismatch`,
`ErrSignatureTargetMismatch` (parallel signing), `ErrMalformedXAdES`,
`ErrUnsupportedDigest`, `ErrInvalidContainer`, `ErrNoDocuments`,
`ErrNoSignatures`.

## Scope / non-goals

- No key handling, no signature *creation* — the signer signs externally
  (wallet / CSC / own tools).
- No in-process signature cryptography — validation SHALL BE delegated to external validation service, `EU DSS` for example.
- Countersignatures are out of scope (parallel/co-signatures only).
