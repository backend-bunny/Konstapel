// Package publish freezes a tested policy bundle and publishes it write-once
// to an OCI registry, so that any retry pushes, or recovers, exactly the same
// bytes.
//
// A frozen bundle is the OCI image layout written by bundlepack plus a
// publication record (publication-record.json) written by Freeze after the
// bundle's declarative policy fixtures passed against the unpacked layer. The
// record binds the source commit, the bundle definition, the manifest, layer
// and content digests, the tools and the tests that ran.
//
// Publish pushes, in order, the config and layer blobs, the manifest by
// digest, the publication record as an OCI referrer of the manifest, and only
// then the version tag, so a tag never names an incomplete subject or a
// subject without its record. Existing content is never uploaded again,
// replaced or deleted. A version tag that already names other bytes is a
// conflict, never moved. After writing, the subject is read back through the
// consumer's retrieval adapter (anonymously, for the official registry) and
// compared with the frozen bytes; the result lists the required proofs
// (signature, provenance) that are still missing, which a ProofCompleter (the
// release signer) adds without touching the subject.
//
// This is a build tool package. It is not linked into the controller or the
// provider.
package publish

import "errors"

// Errors returned by Publish wrap one of these; test with errors.Is.
// Messages never contain credentials.
var (
	// ErrConflict: the version tag already names, or concurrently came to
	// name, a manifest with different content. Nothing was changed.
	ErrConflict = errors.New("a different bundle is already published under this version")
	// ErrIncompleteRemote: a registry request failed while the remote was
	// being brought to the frozen state, or a ProofCompleter failed. Some
	// pieces may be present; rerunning with the same frozen inputs completes
	// exactly the missing ones.
	ErrIncompleteRemote = errors.New("publication is incomplete; rerun with the same frozen inputs")
	// ErrReadBack: after writing, the remote subject could not be read back
	// through the consumer's adapter, or did not match the frozen bytes. The
	// publication must not be reported complete.
	ErrReadBack = errors.New("the published bundle does not read back as frozen")
	// ErrFrozenInputs: the frozen layout or its publication record is missing,
	// invalid or inconsistent, or recovery could not establish the original
	// inputs of an existing publication. Nothing is published in its place.
	ErrFrozenInputs = errors.New("the frozen publication inputs cannot be established")
)
