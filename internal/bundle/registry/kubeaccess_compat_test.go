//go:build registrycompat

package registry_test

// Secret-backed credentials and ConfigMap-backed CAs against the real
// registries of TestRegistryCompat, through kubeaccess.Provider and an
// in-memory object reader. kubeaccess imports this package, so these cases
// live in the external test package and register themselves in
// registry.CompatCases.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

func init() { registry.CompatCases = append(registry.CompatCases, kubeaccessCompat) }

const compatRepoPath = "bundles/konstapel-privileged-containers"

func dockerSecret(host, user, pass string) kubeaccess.Object {
	doc, _ := json.Marshal(map[string]any{"auths": map[string]any{
		host: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))},
	}})
	return kubeaccess.NewObject("kubernetes.io/dockerconfigjson", map[string][]byte{".dockerconfigjson": doc})
}

func caConfigMap(pem []byte) kubeaccess.Object {
	return kubeaccess.NewObject("", map[string][]byte{"ca.crt": pem})
}

func kubeaccessCompat(t *testing.T, env registry.CompatEnv) {
	objs := kubeaccess.NewMemoryReader()
	// The real system roots: the test CA is added to them.
	p, err := kubeaccess.New(kubeaccess.Options{Reader: objs})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := kubeaccess.NewClient(p, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	objs.Put(bundle.KindConfigMap, "registry-ca", caConfigMap(env.CAPEM))
	objs.Put(bundle.KindConfigMap, "other-ca", caConfigMap(env.OtherCAPEM))
	objs.Put(bundle.KindConfigMap, "broken-ca", caConfigMap([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")))
	source := func(host, secret, ca string) bundle.BundleSource {
		s := bundle.BundleSource{Name: "konstapel-privileged-containers", Repository: host + "/" + compatRepoPath,
			CA: &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: ca}}
		if secret != "" {
			s.CredentialSecret = &bundle.ObjectRef{Name: secret}
		}
		return s
	}
	check := func(name string, ok bool, err error, detail string) {
		t.Helper()
		var rerr error
		if !ok {
			rerr = fmt.Errorf("got %v", err)
		}
		env.Record(name, rerr, detail)
		if !ok {
			t.Fatalf("%s: got %v", name, err)
		}
	}

	t.Run("kubeaccess: anonymous retrieval with a ConfigMap CA added to the system roots", func(t *testing.T) {
		res, err := c.Fetch(env.Ctx, source(env.Anon, "", "registry-ca"), env.Pinned)
		check(t.Name(), err == nil, err, "")
		env.CheckFetched(t, res)
	})

	t.Run("kubeaccess: a wrong password in the Secret is refused and never echoed, then the rotated Secret succeeds on the same client", func(t *testing.T) {
		wrong := "wrong-" + env.Pass
		objs.Put(bundle.KindSecret, "registry-creds", dockerSecret(env.Authd, env.User, wrong))
		src := source(env.Authd, "registry-creds", "registry-ca")
		_, err := c.Fetch(env.Ctx, src, env.Pinned)
		out := fmt.Sprintf("%v %+v %#v", err, err, err)
		ok := errors.Is(err, registry.ErrUnauthorized) && !strings.Contains(out, env.Pass)
		check(t.Name()+" (wrong password)", ok, err, "ErrUnauthorized")

		objs.Put(bundle.KindSecret, "registry-creds", dockerSecret(env.Authd, env.User, env.Pass))
		p.Invalidate(bundle.KindSecret, "registry-creds")
		res, err := c.Fetch(env.Ctx, src, env.Pinned)
		check(t.Name()+" (rotated)", err == nil, err, "same Client, Secret rotated and invalidated")
		env.CheckFetched(t, res)
	})

	t.Run("kubeaccess: a missing Secret is ErrCredentials, not anonymous access", func(t *testing.T) {
		// The anonymous registry would serve the request.
		_, err := c.Fetch(env.Ctx, source(env.Anon, "absent-creds", "registry-ca"), env.Pinned)
		check(t.Name(), errors.Is(err, registry.ErrCredentials), err, "")
	})

	t.Run("kubeaccess: an invalid CA object makes the source unavailable", func(t *testing.T) {
		_, err := c.Fetch(env.Ctx, source(env.Anon, "", "broken-ca"), env.Pinned)
		check(t.Name(), errors.Is(err, registry.ErrTrustConfig) && errors.Is(err, kubeaccess.ErrMalformedCA), err, "ErrTrustConfig")
	})

	t.Run("kubeaccess: the CA ConfigMap of registry A does not trust registry B", func(t *testing.T) {
		_, err := c.Fetch(env.Ctx, source(env.Other, "", "registry-ca"), env.Pinned)
		ok := err != nil && strings.Contains(err.Error(), "certificate signed by unknown authority")
		check(t.Name(), ok, err, "x509: unknown authority")
		res, err := c.Fetch(env.Ctx, source(env.Other, "", "other-ca"), env.Pinned)
		check(t.Name()+" (B with its own CA)", err == nil, err, "")
		env.CheckFetched(t, res)
	})
}
