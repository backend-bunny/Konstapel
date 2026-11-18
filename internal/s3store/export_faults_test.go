package s3store

import "testing"

// ServeFakeS3 serves an in-memory S3 server with the given bucket
// versioning ("", "Enabled" or "Suspended") for the external fault-suite
// test, and returns its destination.
func ServeFakeS3(t *testing.T, versioning string) Destination {
	f := newFake()
	f.versioning = versioning
	_, d := f.serve(t)
	return d
}
