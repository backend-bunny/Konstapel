//go:build !unix

package cache

import (
	"fmt"
	"io"
	"os"
)

// lockRoot refuses: without an exclusive lock, Open could not safely treat
// staging directories as abandoned. Konstapel runs only on Linux.
func lockRoot(*os.Root) (io.Closer, error) {
	return nil, fmt.Errorf("%w: the content cache requires a unix platform", ErrConfig)
}
