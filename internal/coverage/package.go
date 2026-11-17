package coverage

// Supporting evidence in assessment packages (add-supporting-evidence-
// attachments 5.2, 5.3).
//
// A platform (Binding-scope) package that reports supporting documents
// carries the run's frozen context at publication.SupportingContextFile and
// an authorized copy of each included document at
// publication.SupportingDocumentDir/<source>. Both are protected roles
// (publication.ProtectedRoles). A namespace package carries neither: its
// coverage report has only the sanitized projection.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// SupportingCopyPath is the package path of a document's included copy.
func SupportingCopyPath(source string) string { return publication.SupportingDocumentDir + source }

// VerifySupportingPackage checks a package's protected supporting evidence
// against its descriptor. Bytes are VerifyDir's; this checks meaning:
//   - the context is the contract (ParseSupportingContext) and valid at the
//     package's closure, available, non-empty, and only for the package's
//     binding;
//   - each included entry's copy is SupportingCopyPath(source), an
//     inventoried supporting document with the entry's sha256 and size;
//   - each supporting document is the copy of exactly one included entry.
//
// A package without supporting files passes.
func VerifySupportingPackage(dir string, d publication.Descriptor) error {
	if !d.Protected() {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(publication.SupportingContextFile)))
	if err != nil {
		return fmt.Errorf("supporting evidence: %w", err)
	}
	return VerifySupportingContext(raw, d)
}

// VerifySupportingContext is VerifySupportingPackage for the context's
// bytes, checked against the descriptor's inventory.
func VerifySupportingContext(raw []byte, d publication.Descriptor) error {
	if d.Scope.Kind != publication.ScopeBinding {
		return errors.New("supporting evidence: only a platform (Binding) package may carry it")
	}
	files := map[string]publication.File{}
	for _, f := range d.Files {
		files[f.Path] = f
	}
	if f, ok := files[publication.SupportingContextFile]; !ok || f.Role != publication.RoleSupportingContext {
		return errors.New("supporting evidence: the context is not inventoried with its role")
	}
	c, err := ParseSupportingContext(raw)
	if err != nil {
		return fmt.Errorf("supporting evidence: %w", err)
	}
	if err := c.validate(d.Window.Closed); err != nil {
		return fmt.Errorf("supporting evidence: %w", err)
	}
	if c.Integration != IntegrationAvailable || len(c.Entries) == 0 {
		return errors.New("supporting evidence: a packaged context must be available and name a document")
	}
	copies := map[string]bool{}
	var errs []error
	for i, e := range c.Entries {
		if e.BindingUID != d.Scope.BindingUID {
			errs = append(errs, fmt.Errorf("supporting evidence: entry %d is for another binding", i))
		}
		if e.Access == AccessRestricted {
			errs = append(errs, fmt.Errorf("supporting evidence: entry %d is a namespace projection", i))
		}
		if e.Access != AccessIncluded {
			continue
		}
		p := SupportingCopyPath(e.Source)
		f, ok := files[p]
		switch {
		case e.Document.Copy != p:
			errs = append(errs, fmt.Errorf("supporting evidence: entry %d's copy is not at %s", i, p))
		case !ok || f.Role != publication.RoleSupportingDocument:
			errs = append(errs, fmt.Errorf("supporting evidence: entry %d's copy %s is not an inventoried supporting document", i, p))
		case f.SHA256 != e.Document.SHA256 || f.Size != e.Document.Size:
			errs = append(errs, fmt.Errorf("supporting evidence: entry %d's copy %s does not match its registered sha256 and size", i, p))
		case copies[p]:
			errs = append(errs, fmt.Errorf("supporting evidence: %s is the copy of more than one entry", p))
		}
		copies[p] = true
	}
	for _, f := range d.Files {
		if f.Role == publication.RoleSupportingDocument && !copies[f.Path] {
			errs = append(errs, fmt.Errorf("supporting evidence: %s is not the copy of an included entry", f.Path))
		}
	}
	return errors.Join(errs...)
}
