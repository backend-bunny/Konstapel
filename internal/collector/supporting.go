package collector

// Supporting-evidence files of a platform package (add-supporting-evidence-
// attachments 5.2, 5.3).
//
// The package owner places them; the attachment owner (the assessment
// controller) decides what they are. A Binding-scope package may carry the
// run's frozen supporting context and verified copies of the documents it
// includes, under publication.SupportingDir with the protected roles, so
// the descriptor records the package's Protection. The OSCAL assessment
// results reference each copy from a back-matter resource by its relative
// path and SHA-256; they create no observation, finding or control result.
// A namespace package never carries either: Export refuses them.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// SupportingFiles are a platform package's supporting-evidence files.
type SupportingFiles struct {
	// Context is the run's frozen supporting context, written verbatim to
	// publication.SupportingContextFile. It is the attachment owner's
	// document; the package owner only places it.
	Context []byte
	// Documents are the verified copies to include.
	Documents []SupportingDocument
}

// SupportingDocument is one document copy to include.
type SupportingDocument struct {
	// ID is the document's opaque identity (the attachment record UID); the
	// copy is placed at publication.SupportingDocumentDir + ID.
	ID string
	// Source is the verified local copy staged by the run.
	Source string
	// SHA256 (lowercase hex) and Size are the registered identity; the copy
	// must match them exactly.
	SHA256 string
	Size   int64
	// Title and MediaType describe the back-matter resource.
	Title, MediaType string
}

var supportingID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// writeSupporting places the supporting files, verifying every copy.
func writeSupporting(req ExportRequest) error {
	s := req.Supporting
	if s == nil {
		return nil
	}
	if req.Scope.Kind != publication.ScopeBinding {
		return fmt.Errorf("a %s package cannot carry protected supporting evidence", req.Scope.Kind)
	}
	if len(s.Context) == 0 {
		return errors.New("supporting evidence requires its context")
	}
	dir := filepath.Join(req.Out, filepath.FromSlash(publication.SupportingDocumentDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(req.Out, filepath.FromSlash(publication.SupportingContextFile)), s.Context, 0o644); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, d := range s.Documents {
		if !supportingID.MatchString(d.ID) || seen[d.ID] {
			return fmt.Errorf("supporting document identity %q is invalid or repeated", d.ID)
		}
		seen[d.ID] = true
		if err := copyVerified(d.Source, filepath.Join(dir, d.ID), d.SHA256, d.Size); err != nil {
			return fmt.Errorf("supporting document %s: %w", d.ID, err)
		}
	}
	return nil
}

// ErrSupportingCopy marks a staged copy that no longer matches its
// registered identity.
var ErrSupportingCopy = errors.New("staged supporting copy does not match its registered sha256 and size")

func copyVerified(from, to, sha string, size int64) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != sha {
		_ = os.Remove(to)
		return ErrSupportingCopy
	}
	return nil
}

// supportingResources are the back-matter resources of the included
// copies: relative links with their SHA-256, never a live storage link.
func supportingResources(s *SupportingFiles) []oscal.Resource {
	if s == nil {
		return nil
	}
	var out []oscal.Resource
	for _, d := range s.Documents {
		mt := d.MediaType
		if mt == "" {
			mt = "application/octet-stream"
		}
		out = append(out, oscal.Resource{UUID: uuid.NewString(), Title: strings.TrimSpace(d.Title),
			Description: "Supporting document copied into this package from a platform evidence attachment. It is supporting material, not a finding or control result.",
			Props:       &[]oscal.Property{{Name: "supporting-document", Ns: ns, Value: d.ID}},
			Rlinks: &[]oscal.ResourceLink{{Href: publication.SupportingDocumentDir + d.ID, MediaType: mt,
				Hashes: &[]oscal.Hash{{Algorithm: "SHA-256", Value: d.SHA256}}}}})
	}
	return out
}
