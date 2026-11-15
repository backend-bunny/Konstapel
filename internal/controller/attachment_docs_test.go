package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	attfake "github.com/backend-bunny/Konstapel/internal/attachments/fake"
)

// add-supporting-evidence-attachments 4.4: the lifecycle examples in
// docs/supporting-evidence.md run against the controller with an injected
// clock and the storage contract's in-memory implementation.

// staticStores serves one store for every pinned destination.
type staticStores struct{ st attachments.Store }

func (s staticStores) Store(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) {
	return s.st, nil
}

// documentedTable returns the cells of the table rows that follow heading
// in docs/supporting-evidence.md, skipping its header and separator.
func documentedTable(t *testing.T, heading, header string) [][]string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), heading)
	_, rest, ok2 := strings.Cut(section, header)
	if !ok || !ok2 {
		t.Fatalf("table %q under %q not found", header, heading)
	}
	var rows [][]string
	for _, line := range strings.Split(rest, "\n")[2:] {
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("table %q is empty", header)
	}
	return rows
}

func ticked(cell string) string {
	_, rest, _ := strings.Cut(cell, "`")
	v, _, _ := strings.Cut(rest, "`")
	return v
}

func TestDocumentedAttachmentTimeline(t *testing.T) {
	rows := documentedTable(t, "### Example timeline", "| Time (UTC) | What happens | Validity | Content | Withdrawal |")
	digest := vendoredDigest(t)
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"),
		baselineProfile(digest), resolvedBinding("a", "uid-a", 1, digest))
	store := attfake.New(func() time.Time { return f.now })
	f.r.Storage.Stores = staticStores{store}
	ctx := context.Background()
	const name = "dc-north-physical-access-2026"
	doc := []byte("%PDF-1.7 DC North physical access control audit 2026")
	sum := sha256.Sum256(doc)
	var first attachments.Receipt
	var uid types.UID
	upload := func(who string) attachments.Receipt {
		t.Helper()
		a := f.get(name)
		ref := attachments.Ref{ClusterID: "kube-system:cluster", UID: string(a.UID)}
		if _, err := store.Stage(ctx, attachments.StageRequest{Ref: ref, Document: attachments.Expected(a.Spec), Uploader: attachments.Principal{Username: who},
			Body: bytes.NewReader(doc)}); err != nil {
			t.Fatal(err)
		}
		r, err := store.Commit(ctx, attachments.CommitRequest{Ref: ref, SpecDigest: attachments.SpecDigest(a.Spec), Document: attachments.Expected(a.Spec),
			ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: attachments.DefaultRetention})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var prev time.Time
	var prevRequeue time.Duration
	for _, row := range rows {
		at, err := time.Parse(time.RFC3339, row[0])
		if err != nil {
			t.Fatalf("row %v: %v", row, err)
		}
		f.now = at
		what := row[1]
		switch {
		case strings.HasPrefix(what, "registered"):
			a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, UID: "dc-uid", Generation: 1}, Spec: v1alpha1.EvidenceAttachmentSpec{
				Document: v1alpha1.AttachmentDocument{Title: "DC North physical access control audit 2026", MediaType: "application/pdf", Size: int64(len(doc)),
					SHA256: "sha256:" + hex.EncodeToString(sum[:])},
				Source:       v1alpha1.AttachmentSource{Issuer: "Example Audit AB"},
				Validity:     v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), ValidUntil: metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))},
				Associations: []v1alpha1.AttachmentAssociation{f.association("a", "uid-a")},
				Scope:        v1alpha1.AttachmentScope{Description: "DC North"},
				RegisteredBy: &v1alpha1.Requester{Username: "platform-registrar"}}}
			if err := f.c.Create(ctx, a); err != nil {
				t.Fatal(err)
			}
			uid = a.UID
		case strings.HasPrefix(what, "uploaded and committed"):
			first = upload("platform-uploader")
			if !strings.Contains(what, "`expiresAt` is "+first.ExpiresAt.Format(time.RFC3339)) {
				t.Fatalf("documented %q; committed expiresAt %s", what, first.ExpiresAt.Format(time.RFC3339))
			}
		case strings.Contains(what, "uploaded again"):
			again := upload("another-uploader")
			if again.Uploader != first.Uploader || !again.CommittedAt.Equal(first.CommittedAt) || !again.ExpiresAt.Equal(first.ExpiresAt) {
				t.Fatalf("a re-upload renewed the commitment: %+v, first %+v", again, first)
			}
		case strings.Contains(what, "deleted"):
			if err := f.c.Delete(ctx, f.get(name)); err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(what, "nothing"):
			// No event: the controller must already be scheduled to wake by now.
			if strings.Contains(what, "timer") && (prevRequeue <= 0 || prev.Add(prevRequeue).After(at)) {
				t.Fatalf("%s: the controller was not scheduled to wake (last pass %s requeued %v)", row[0], prev.Format(time.RFC3339), prevRequeue)
			}
		default:
			t.Fatalf("unknown event %q", what)
		}
		prev = at
		prevRequeue = f.settleOrRelease(name).RequeueAfter
		err = f.c.Get(ctx, client.ObjectKey{Name: name}, &v1alpha1.EvidenceAttachment{})
		if strings.HasPrefix(row[4], "released") {
			if !apierrors.IsNotFound(err) {
				t.Fatalf("%s: not released: %v", row[0], err)
			}
			if _, err := store.Committed(ctx, attachments.Ref{ClusterID: "kube-system:cluster", UID: string(uid)}); err == nil {
				t.Fatalf("%s: the owned source remains", row[0])
			}
			continue
		}
		a := f.get(name)
		state, next := validityOf(a)
		want, until, _ := strings.Cut(row[2], " until ")
		if string(state) != strings.Trim(want, "`") || (until == "") != (next == nil) || (next != nil && next.UTC().Format(time.RFC3339) != until) {
			t.Fatalf("%s: validity %s next %v, documented %q", row[0], state, next, row[2])
		}
		if got := contentOf(a); got != ticked(row[3]) {
			t.Fatalf("%s: content %s, documented %q", row[0], got, row[3])
		}
		switch w := row[4]; {
		case w == "no":
			if a.Status.Withdrawal != nil {
				t.Fatalf("%s: withdrawn", row[0])
			}
		case strings.HasPrefix(w, "withdrawn"):
			if a.Status.Withdrawal == nil || !strings.Contains(w, "SourceRetained="+condition(a, v1alpha1.ConditionSourceRetained)) {
				t.Fatalf("%s: withdrawal %+v, retention %s, documented %q", row[0], a.Status.Withdrawal, condition(a, v1alpha1.ConditionSourceRetained), w)
			}
		default:
			t.Fatalf("unknown withdrawal cell %q", w)
		}
	}
}

// settleOrRelease reconciles until the record writes nothing more or is
// released, and returns the last result.
func (f *storageFixture) settleOrRelease(name string) (res ctrl.Result) {
	f.t.Helper()
	for range 6 {
		before := &v1alpha1.EvidenceAttachment{}
		if err := f.c.Get(context.Background(), client.ObjectKey{Name: name}, before); apierrors.IsNotFound(err) {
			return res
		}
		r, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
		if err != nil {
			f.t.Fatal(err)
		}
		res = r
		after := &v1alpha1.EvidenceAttachment{}
		if err := f.c.Get(context.Background(), client.ObjectKey{Name: name}, after); apierrors.IsNotFound(err) || after.ResourceVersion == before.ResourceVersion {
			return res
		}
	}
	f.t.Fatalf("%s does not settle", name)
	return res
}

func TestDocumentedCleanupBackoff(t *testing.T) {
	rows := documentedTable(t, "### Recovery", "| Failed attempts | Next attempt after |")
	for _, row := range rows {
		want, err := time.ParseDuration(row[1])
		if err != nil {
			t.Fatal(err)
		}
		from, more := strings.CutSuffix(row[0], " or more")
		n, err := strconv.Atoi(from)
		if err != nil {
			t.Fatal(err)
		}
		last := n
		if more {
			last = n + 10
		}
		for a := n; a <= last; a++ {
			if got := cleanupBackoff(int32(a)); got != want {
				t.Errorf("after %d failed attempts: %v, documented %v", a, got, want)
			}
		}
	}
}

// A correction is a new record: the expired original stays expired (and
// leaves new coverage once withdrawn) while the corrected record is current.
func TestAttachmentCorrectionIsANewRecord(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	f.now = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	f.create("original", f.association("a", "uid-a"))
	f.createValid("corrected", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC), f.association("a", "uid-a"))
	for _, n := range []string{"original", "corrected"} {
		f.settle(n)
		f.commit(n, "dest-1", nil)
		f.settle(n)
	}
	if s, _ := validityOf(f.get("original")); s != v1alpha1.TemporalExpired {
		t.Fatalf("original: %s", s)
	}
	if s, _ := validityOf(f.get("corrected")); s != v1alpha1.TemporalCurrent {
		t.Fatalf("corrected: %s", s)
	}
	if err := f.c.Delete(ctx, f.get("original")); err != nil {
		t.Fatal(err)
	}
	f.settle("original")
	var list v1alpha1.EvidenceAttachmentList
	if err := f.c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	obs := attachments.ForBinding(list.Items, "uid-a", f.now)
	if len(obs) != 1 || obs[0].Name != "corrected" || obs[0].Temporal != v1alpha1.TemporalCurrent {
		t.Fatalf("new coverage: %+v", obs)
	}
	if a := f.get("original"); a.Status.Storage.Commitment == nil || condition(a, v1alpha1.ConditionSourceRetained) != "True/RetentionActive" {
		t.Fatalf("the withdrawn original lost its retained source: %+v", a.Status.Storage)
	}
}
