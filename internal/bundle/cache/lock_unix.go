//go:build unix

package cache

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// lockRoot takes an exclusive, non-blocking flock on the cache root's lock
// file for the life of the Cache. It is what lets Open treat every staging
// directory as abandoned: no other Cache, in this or another process, can be
// writing under the same root.
func lockRoot(root *os.Root) (io.Closer, error) {
	f, err := root.OpenFile(lockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrInUse, err)
	}
	return f, nil
}
