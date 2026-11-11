package cache

import (
	"errors"
	"fmt"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Errors. Every failure wraps exactly one of these so callers can classify it
// with errors.Is.
var (
	// ErrConfig: the limits or configuration are invalid.
	ErrConfig = errors.New("invalid cache configuration")
	// ErrInUse: another Cache holds the root's lock.
	ErrInUse = errors.New("cache root is in use")
	// ErrClosed: the Cache was closed.
	ErrClosed = errors.New("cache is closed")
	// ErrMalformed: the manifest or archive cannot be decoded: corrupt or
	// truncated gzip or tar, trailing data, a second gzip member.
	ErrMalformed = errors.New("malformed bundle")
	// ErrUnsafeEntry: an archive entry is not a plain regular file at an
	// allowed, portable, collision-free path.
	ErrUnsafeEntry = errors.New("unsafe archive entry")
	// ErrLimit: the bundle exceeds a configured size, count or name limit.
	ErrLimit = errors.New("bundle exceeds a limit")
	// ErrIntegrity: the manifest and layer bytes do not match each other or
	// their digests.
	ErrIntegrity = errors.New("bundle bytes do not match their digests")
	// ErrInventory: the payload does not match bundle.json's file inventory,
	// or bundle.json is missing or invalid.
	ErrInventory = errors.New("payload does not match its inventory")
	// ErrContent: the configured content check rejected the payload.
	ErrContent = errors.New("bundle content check failed")
	// ErrCapacity: the cache cannot reserve room for the entry. Nothing was
	// written and existing entries are intact.
	ErrCapacity = errors.New("cache capacity exhausted")
	// ErrNoSpace: the filesystem ran out of space (ENOSPC) while staging.
	// The staging directory was removed and existing entries are intact.
	ErrNoSpace = errors.New("no space left for the cache")
	// ErrNotFound: no entry for the digest.
	ErrNotFound = errors.New("cache entry not found")
	// ErrCorrupt: a stored entry failed its integrity check on reuse. It was
	// removed and is never served.
	ErrCorrupt = errors.New("cache entry is corrupt")
)

const (
	// blockSize is the allocation unit capacity accounting charges: every
	// file, directory and blob costs its size rounded up to whole blocks, at
	// least one block.
	blockSize = 4096
	// stagingOverhead is charged on top of an entry while it stages: the
	// staging directory and its blobs directory.
	stagingOverhead = 2 * blockSize
	// metadataPerEntry bounds the decompressed tar metadata (headers, PAX
	// records, padding) per archive entry; with MaxUnpackedBytes it bounds
	// the whole decompressed stream.
	metadataPerEntry = 16 << 10
	// maxRecordBytes bounds the integrity record read back from disk.
	maxRecordBytes = 64 << 10
	// upper bounds that keep the cost arithmetic far from overflow.
	maxByteLimit = 1 << 40
	maxFileLimit = 1 << 20
)

// Limits bound everything a bundle can make the cache read, decompress or
// write. DefaultLimits documents the defaults.
type Limits struct {
	// MaxManifestBytes bounds the OCI manifest.
	MaxManifestBytes int64
	// MaxCompressedBytes bounds the tar+gzip layer as stored and as read.
	MaxCompressedBytes int64
	// MaxUnpackedBytes bounds the sum of all regular-file sizes extracted.
	MaxUnpackedBytes int64
	// MaxFiles bounds the regular files in the archive, bundle.json
	// included. Directories implied by the paths are bounded by the same
	// number.
	MaxFiles int
	// MaxDescriptorBytes bounds bundle.json, which is held in memory.
	MaxDescriptorBytes int64
	// MaxPathBytes bounds a whole archive path; MaxNameBytes one component.
	MaxPathBytes int
	MaxNameBytes int
	// MaxDepth bounds the number of path components.
	MaxDepth int
	// CapacityBytes bounds everything under the cache root that the cache
	// owns: stored blobs, extracted entries, integrity records and in-flight
	// staging, each charged in whole 4 KiB blocks.
	CapacityBytes int64
}

// DefaultLimits are the documented defaults (docs/policy-bundles.md, "Safe
// materialization and the content cache"): 4 MiB manifest and 64 MiB
// compressed payload (the registry adapter's limits), 256 MiB unpacked and
// 4096 regular files (bundle.Unpack's), and a 1 GiB cache.
func DefaultLimits() Limits {
	return Limits{
		MaxManifestBytes:   4 << 20,
		MaxCompressedBytes: 64 << 20,
		MaxUnpackedBytes:   bundle.MaxPayloadBytes,
		MaxFiles:           bundle.MaxFiles,
		MaxDescriptorBytes: 4 << 20,
		MaxPathBytes:       1024,
		MaxNameBytes:       255,
		MaxDepth:           32,
		CapacityBytes:      1 << 30,
	}
}

// Validate rejects limits that are non-positive, beyond what a filesystem
// can represent, contradictory, or too small for the cache to hold even one
// maximal entry while it stages.
func (l Limits) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	for name, v := range map[string]int64{
		"MaxManifestBytes": l.MaxManifestBytes, "MaxCompressedBytes": l.MaxCompressedBytes,
		"MaxUnpackedBytes": l.MaxUnpackedBytes, "MaxDescriptorBytes": l.MaxDescriptorBytes,
		"CapacityBytes": l.CapacityBytes,
	} {
		if v <= 0 || v > maxByteLimit {
			fail("%s %d must be between 1 and %d", name, v, int64(maxByteLimit))
		}
	}
	if l.MaxFiles <= 0 || l.MaxFiles > maxFileLimit {
		fail("MaxFiles %d must be between 1 and %d", l.MaxFiles, maxFileLimit)
	}
	if l.MaxNameBytes <= 0 || l.MaxNameBytes > 255 {
		fail("MaxNameBytes %d must be between 1 and 255 (the usual filesystem limit)", l.MaxNameBytes)
	}
	if l.MaxPathBytes < l.MaxNameBytes || l.MaxPathBytes > 3072 {
		fail("MaxPathBytes %d must be between MaxNameBytes and 3072 (room below PATH_MAX for the cache root)", l.MaxPathBytes)
	}
	if l.MaxDepth <= 0 || l.MaxDepth > 255 {
		fail("MaxDepth %d must be between 1 and 255", l.MaxDepth)
	}
	if l.MaxDescriptorBytes > l.MaxUnpackedBytes {
		fail("MaxDescriptorBytes %d exceeds MaxUnpackedBytes %d", l.MaxDescriptorBytes, l.MaxUnpackedBytes)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if worst := l.worstCaseReservation(); l.CapacityBytes < worst {
		return fmt.Errorf("%w: CapacityBytes %d cannot hold one maximal entry while it stages (%d)", ErrConfig, l.CapacityBytes, worst)
	}
	return nil
}

// worstCaseReservation is the most one Put can reserve under these limits.
func (l Limits) worstCaseReservation() int64 {
	files := int64(l.MaxFiles)
	tree := l.MaxUnpackedBytes + files*blockSize + // each file rounds up by less than a block
		files*blockSize + // at most MaxFiles implied directories
		2*blockSize // the entry and tree directories
	return blocks(l.MaxManifestBytes) + blocks(l.MaxCompressedBytes) + tree + blocks(maxRecordBytes) + stagingOverhead
}

// blocks is the capacity charge for a file of n bytes.
func blocks(n int64) int64 {
	if n <= 0 {
		return blockSize
	}
	return (n + blockSize - 1) / blockSize * blockSize
}

// Config configures a Cache.
type Config struct {
	// Limits; the zero value means DefaultLimits.
	Limits Limits
	// CheckContent runs on the verified staging tree before promotion. nil
	// means bundle.ValidateContentDir. It must only read dir. Its verdict is a
	// gate on what is stored, not acceptance: compatibility and trust are
	// evaluated separately each time an entry is used.
	CheckContent func(d *bundle.Descriptor, dir string) error
	// Now stamps last use; nil means time.Now.
	Now func() time.Time

	// wrapFS lets tests inject failures over the real filesystem.
	wrapFS func(fileSystem) fileSystem
}
