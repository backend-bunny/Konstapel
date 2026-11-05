package assessment

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ValidateReferences checks OSCAL UUID references against the linked package and
// checks every local href exists, including fragments in referenced documents.
func ValidateReferences(out string) error {
	docs := map[string]any{}
	ids := map[string]bool{}
	for _, name := range []string{"assessment-plan.json", "assessment-results.json", "system-security-plan.json"} {
		var d any
		if err := Read(filepath.Join(out, name), &d); err != nil {
			return err
		}
		docs[name] = d
	}
	var walk func(any, func(string, any) error) error
	walk = func(v any, f func(string, any) error) error {
		switch x := v.(type) {
		case map[string]any:
			for k, y := range x {
				if err := f(k, y); err != nil {
					return err
				}
				if err := walk(y, f); err != nil {
					return err
				}
			}
		case []any:
			for _, y := range x {
				if err := walk(y, f); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, d := range docs {
		_ = walk(d, func(k string, v any) error {
			if k == "uuid" {
				ids[Str(v)] = true
			}
			return nil
		})
	}
	for name, d := range docs {
		if err := walk(d, func(k string, v any) error {
			if strings.HasSuffix(k, "-uuid") && !ids[Str(v)] {
				return fmt.Errorf("%s dangling %s %v", name, k, v)
			}
			if k != "href" {
				return nil
			}
			s := Str(v)
			u, err := url.Parse(s)
			if err != nil {
				return err
			}
			if u.IsAbs() {
				return nil
			}
			if u.Path == "" {
				if u.Fragment != "" && !ids[u.Fragment] {
					return fmt.Errorf("dangling fragment %s", s)
				}
				return nil
			}
			path := filepath.Join(out, filepath.FromSlash(u.Path))
			rel, e := filepath.Rel(out, path)
			if e != nil || strings.HasPrefix(rel, "..") {
				return fmt.Errorf("evidence escapes package: %s", s)
			}
			if _, err = os.Stat(path); err != nil {
				return fmt.Errorf("missing local evidence %s: %w", s, err)
			}
			if u.Fragment != "" {
				var target any
				if err = Read(path, &target); err != nil {
					return err
				}
				found := false
				_ = walk(target, func(k string, v any) error {
					if k == "uuid" && v == u.Fragment {
						found = true
					}
					return nil
				})
				if !found {
					return fmt.Errorf("unresolved fragment %s", s)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
