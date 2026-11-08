package download

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

// DefaultReloadInterval is how often mounted TLS files are re-read. The
// kubelet updates Secret volumes within about a minute of a rotation, so a
// renewed certificate is served without a restart.
const DefaultReloadInterval = 10 * time.Second

// Certificates is the download server's serving certificate, reloaded from
// its mounted files. A rotated certificate, key or CA bundle is served only
// after it passes the same checks as at startup; until then the last good
// certificate keeps serving and Ready reports the problem, so a broken
// rotation removes the endpoint from its Service instead of serving a
// certificate clients cannot trust. Authorization is unaffected either way.
type Certificates struct {
	CertFile, KeyFile, CAFile string
	// Names are the service names clients use.
	Names []string
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.RWMutex
	current *tls.Certificate
	loaded  material
	err     error
}

// LoadCertificates verifies and loads the initial certificate. It fails
// when the files are invalid, so the server never starts with them.
func LoadCertificates(certFile, keyFile, caFile string, names []string) (*Certificates, error) {
	c := &Certificates{CertFile: certFile, KeyFile: keyFile, CAFile: caFile, Names: names}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Certificates) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Reload re-reads the files. Changed material replaces the served
// certificate only when it is valid; otherwise the error is kept for Ready.
func (c *Certificates) Reload() error {
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("a TLS certificate and key are required")
	}
	m, err := readMaterial(c.CertFile, c.KeyFile, c.CAFile)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil && c.current != nil && m.equal(c.loaded) {
		c.err = nil
		return nil
	}
	var pair *tls.Certificate
	if err == nil {
		pair, err = m.verify(c.Names, c.now())
	}
	if err != nil {
		c.err = err
		return err
	}
	c.current, c.loaded, c.err = pair, m, nil
	return nil
}

// Watch reloads every interval until ctx ends.
func (c *Certificates) Watch(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Reload(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// GetCertificate serves the last verified certificate.
func (c *Certificates) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.current == nil {
		return nil, errors.New("no TLS certificate loaded")
	}
	return c.current, nil
}

// Ready reports whether the configured certificate is usable now: the last
// reload succeeded and the served certificate has not expired since.
func (c *Certificates) Ready() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.err != nil {
		return c.err
	}
	if c.current == nil {
		return errors.New("no TLS certificate loaded")
	}
	return validAt(c.current.Leaf, c.now())
}
