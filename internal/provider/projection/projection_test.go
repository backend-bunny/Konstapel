package projection

import (
	"errors"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	ns := Scope{Name: "shop-dev", UID: "uid-shop-dev"}
	ok := []Disclosure{{Item: "a", Namespace: "shop-dev", NamespaceUID: "uid-shop-dev"}, {Item: "b", NamespaceUID: "uid-shop-dev"}, {Item: "c", Namespace: "shop-dev"}}
	if err := Check(ns, ok); err != nil {
		t.Fatal(err)
	}
	if err := Check(ns, nil); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ns   Scope
		item Disclosure
		why  string
	}{
		"unknown scope":            {ns, Disclosure{Item: "x"}, "x: unknown scope"},
		"sibling instance":         {ns, Disclosure{Item: "x", NamespaceUID: "uid-shop-prod"}, "x: another namespace instance"},
		"sibling name":             {ns, Disclosure{Item: "x", Namespace: "shop-prod"}, "x: another namespace"},
		"sibling name, own UID":    {ns, Disclosure{Item: "x", Namespace: "shop-prod", NamespaceUID: "uid-shop-dev"}, "x: another namespace"},
		"own name, sibling UID":    {ns, Disclosure{Item: "x", Namespace: "shop-dev", NamespaceUID: "uid-shop-prod"}, "x: another namespace instance"},
		"name the scope can't see": {Scope{UID: "uid-shop-dev"}, Disclosure{Item: "x", Namespace: "shop-dev"}, "x: a namespace name the scope cannot check"},
		"scope without instance":   {Scope{Name: "shop-dev"}, Disclosure{Item: "x", Namespace: "shop-dev"}, "names no namespace instance"},
	} {
		err := Check(tc.ns, append(ok[:2:2], tc.item))
		if !errors.Is(err, ErrDisclosure) || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// A refusal locates the item; it never repeats a namespace.
		for _, leak := range []string{"shop-prod", "uid-shop-prod"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the refusal repeats %q: %v", name, leak, err)
			}
		}
	}
	many := make([]Disclosure, 3*maxErrors)
	if err := Check(ns, many); err == nil || !strings.Contains(err.Error(), "and 40 more") || strings.Count(err.Error(), "unknown scope") != maxErrors {
		t.Fatalf("refusals are not bounded: %v", err)
	}
}
