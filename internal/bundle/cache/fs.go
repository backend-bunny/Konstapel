package cache

import (
	"io"
	"io/fs"
	"os"
)

// fileSystem is every filesystem operation the cache performs, on slash
// paths relative to the cache root. It exists so tests can inject failures
// (ENOSPC, an interruption at any step, a panic) on top of the real disk; the
// production implementation is osFS.
type fileSystem interface {
	// Mkdir creates exactly one directory and fails if anything exists there.
	Mkdir(name string, perm fs.FileMode) error
	// Create makes a new regular file. It fails if anything, including a
	// symlink, exists at name: the cache never opens a pre-existing path for
	// writing.
	Create(name string, perm fs.FileMode) (writer, error)
	Open(name string) (fs.File, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Lstat(name string) (fs.FileInfo, error)
	Rename(oldname, newname string) error
	RemoveAll(name string) error
	// SyncDir flushes a directory, making renames and creations in it durable.
	SyncDir(name string) error
}

type writer interface {
	io.Writer
	Sync() error
	Close() error
}

// osFS confines every operation to the cache root with os.Root, which refuses
// any path or symlink that would leave it. This is defense in depth: archive
// paths are validated before they reach the filesystem, and files are
// created with O_CREATE|O_EXCL, which never follows a final symlink.
type osFS struct{ root *os.Root }

func (o osFS) Mkdir(name string, perm fs.FileMode) error { return o.root.Mkdir(name, perm) }

func (o osFS) Create(name string, perm fs.FileMode) (writer, error) {
	return o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

func (o osFS) Open(name string) (fs.File, error)          { return o.root.Open(name) }
func (o osFS) Lstat(name string) (fs.FileInfo, error)     { return o.root.Lstat(name) }
func (o osFS) Rename(oldname, newname string) error       { return o.root.Rename(oldname, newname) }
func (o osFS) RemoveAll(name string) error                { return o.root.RemoveAll(name) }
func (o osFS) ReadDir(name string) ([]fs.DirEntry, error) { return readDir(o.root, name) }

func readDir(root *os.Root, name string) ([]fs.DirEntry, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func (o osFS) SyncDir(name string) error {
	f, err := o.root.Open(name)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
