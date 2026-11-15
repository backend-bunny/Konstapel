package main

// `konstapel evidence` (add-supporting-evidence-attachments 3.3): the
// platform workflow for supporting-evidence documents. It talks only to the
// Kubernetes API (with the caller's kubeconfig) and to the download service
// (with a bearer token for its audience). It never starts the C2P provider,
// renders or delivers policies, fetches a declared source URL, or opens a
// document's contents.
//
//	konstapel evidence register -f attachment.yaml --document report.pdf [--dry-run]
//	konstapel evidence upload   NAME --uid UID --file report.pdf --server URL --token-file F [--ca-file F]
//	konstapel evidence download NAME --uid UID --output copy.pdf --server URL --token-file F [--ca-file F]
//	konstapel evidence status   NAME [--uid UID] [-o json]

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/download"
)

const evidenceUsage = `usage: konstapel evidence <command> [flags]

Commands:
  register  -f attachment.yaml --document FILE [--dry-run]
            complete the document identity from FILE and the exact binding
            UIDs from the cluster, then create the EvidenceAttachment
  upload    NAME --uid UID --file FILE --server URL --token-file FILE
            send the registered document to the download service
  download  NAME --uid UID --output FILE --server URL --token-file FILE
            fetch and verify the committed document
  status    NAME [--uid UID] [-o json]
            show identity, validity, associations and storage state

Kubernetes flags (every command): --kubeconfig, --context, --request-timeout.
Transfer flags (upload, download): --server, --ca-file, --token-file, --timeout.`

// evidenceCmd holds the parsed flags of one command.
type evidenceCmd struct {
	stdout, stderr io.Writer

	kubeconfig, context string
	requestTimeout      time.Duration

	server, caFile, tokenFile string
	timeout                   time.Duration

	// pinWait bounds how long upload waits for the controller to pin a
	// new record's storage destination.
	pinWait time.Duration

	newClient func() (client.Client, error)
	http      *http.Client
}

// runEvidence dispatches `konstapel evidence <command>`.
func runEvidence(args []string, stdout, stderr io.Writer) error {
	return (&evidenceCmd{stdout: stdout, stderr: stderr}).run(args)
}

func (e *evidenceCmd) run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(e.stderr, evidenceUsage)
		if len(args) == 0 {
			return errors.New("a command is required")
		}
		return nil
	}
	fs := flag.NewFlagSet("evidence "+args[0], flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.StringVar(&e.kubeconfig, "kubeconfig", "", "kubeconfig file (default: KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&e.context, "context", "", "kubeconfig context (default: the current context)")
	fs.DurationVar(&e.requestTimeout, "request-timeout", 30*time.Second, "timeout of each Kubernetes API request")
	if e.newClient == nil {
		e.newClient = e.kubeClient
	}
	switch args[0] {
	case "register":
		file := fs.String("f", "", "EvidenceAttachment manifest (YAML or JSON)")
		doc := fs.String("document", "", "the document file whose size and SHA-256 are registered")
		dry := fs.Bool("dry-run", false, "validate with a server-side dry run and print the completed record without creating it")
		if _, err := parseInterspersed(fs, args[1:], 0); err != nil {
			return err
		}
		return e.register(*file, *doc, *dry)
	case "upload", "download":
		uid := fs.String("uid", "", "the record's exact UID (required)")
		file := fs.String("file", "", "the document to upload")
		out := fs.String("output", "", "where to write the downloaded document (must not exist)")
		fs.DurationVar(&e.pinWait, "pin-wait", time.Minute, "upload: how long to wait for the controller to pin a new record's storage destination")
		e.transferFlags(fs)
		pos, err := parseInterspersed(fs, args[1:], 1)
		if err != nil {
			return err
		}
		if args[0] == "upload" {
			return e.upload(pos[0], *uid, *file)
		}
		return e.download(pos[0], *uid, *out)
	case "status":
		uid := fs.String("uid", "", "the record's exact UID (optional check)")
		output := fs.String("o", "text", "output format: text or json")
		pos, err := parseInterspersed(fs, args[1:], 1)
		if err != nil {
			return err
		}
		return e.status(pos[0], *uid, *output)
	}
	fmt.Fprintln(e.stderr, evidenceUsage)
	return fmt.Errorf("unknown evidence command %q", args[0])
}

func (e *evidenceCmd) transferFlags(fs *flag.FlagSet) {
	fs.StringVar(&e.server, "server", "", "download service base URL, https:// only (required)")
	fs.StringVar(&e.caFile, "ca-file", "", "CA bundle that signs the download service certificate (default: system roots)")
	fs.StringVar(&e.tokenFile, "token-file", "", "file holding a bearer token for the download service audience (required)")
	fs.DurationVar(&e.timeout, "timeout", 10*time.Minute, "overall transfer timeout")
}

// parseInterspersed parses flags around exactly want positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string, want int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != want {
		if want == 0 {
			return nil, fmt.Errorf("unexpected arguments %q", pos)
		}
		return nil, fmt.Errorf("expected one EvidenceAttachment name, got %q", pos)
	}
	return pos, nil
}

// restConfig loads the kubeconfig like kubectl: --kubeconfig, else
// KUBECONFIG, else ~/.kube/config, with --context overriding the current
// context.
func (e *evidenceCmd) restConfig() (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if e.kubeconfig != "" {
		rules.ExplicitPath = e.kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: e.context}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w (select one with --kubeconfig or KUBECONFIG, and a context with --context)", err)
	}
	cfg.Timeout, cfg.UserAgent = e.requestTimeout, "konstapel-evidence"
	return cfg, nil
}

func (e *evidenceCmd) kubeClient() (client.Client, error) {
	cfg, err := e.restConfig()
	if err != nil {
		return nil, err
	}
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: s})
}

// apiError makes a Kubernetes API error actionable.
func apiError(what string, err error, role string) error {
	switch {
	case apierrors.IsNotFound(err):
		return fmt.Errorf("%s: not found in this cluster (check --context)", what)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("%s: forbidden; this needs %s: %v", what, role, err)
	case apierrors.IsUnauthorized(err):
		return fmt.Errorf("%s: the kubeconfig credentials were not accepted: %v", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// record reads an EvidenceAttachment and, when uid is set, requires it.
func (e *evidenceCmd) record(ctx context.Context, c client.Client, name, uid, role string) (*v1alpha1.EvidenceAttachment, error) {
	a := &v1alpha1.EvidenceAttachment{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, a); err != nil {
		return nil, apiError("EvidenceAttachment "+name, err, role)
	}
	if uid != "" && string(a.UID) != uid {
		return nil, fmt.Errorf("EvidenceAttachment %s has UID %s, not %s: it was recreated, or the UID belongs to another record; nothing was transferred", name, a.UID, uid)
	}
	return a, nil
}

// fileDocument hashes a local file.
func fileDocument(path string) (attachments.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return attachments.Document{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return attachments.Document{}, err
	}
	return attachments.Document{SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// register completes and creates a record. The manifest is the reviewable
// registration; the command fills only the document identity (from the
// file) and missing binding UIDs (from the cluster), and refuses values
// that disagree with either.
func (e *evidenceCmd) register(file, docPath string, dry bool) error {
	if file == "" || docPath == "" {
		return errors.New("register needs -f MANIFEST and --document FILE")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	a := &v1alpha1.EvidenceAttachment{}
	if err := yaml.UnmarshalStrict(raw, a); err != nil {
		return fmt.Errorf("%s: %w (only EvidenceAttachment fields are accepted)", file, err)
	}
	if a.APIVersion != v1alpha1.GroupVersion.String() || a.Kind != "EvidenceAttachment" {
		return fmt.Errorf("%s: expected apiVersion %s and kind EvidenceAttachment", file, v1alpha1.GroupVersion)
	}
	if a.Name == "" {
		return fmt.Errorf("%s: metadata.name is required", file)
	}
	if a.Spec.RegisteredBy != nil {
		return fmt.Errorf("%s: remove spec.registeredBy; admission records the authenticated registrant", file)
	}
	if !emptyStatus(a.Status) {
		return fmt.Errorf("%s: remove status; only the controller writes it", file)
	}
	doc, err := fileDocument(docPath)
	if err != nil {
		return err
	}
	if d := a.Spec.Document; (d.SHA256 != "" && d.SHA256 != doc.SHA256) || (d.Size != 0 && d.Size != doc.Size) {
		return fmt.Errorf("%s declares %s (%d bytes), but %s is %s (%d bytes): register the file you will upload", file, d.SHA256, d.Size, docPath, doc.SHA256, doc.Size)
	}
	a.Spec.Document.SHA256, a.Spec.Document.Size = doc.SHA256, doc.Size
	c, err := e.newClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*e.requestTimeout)
	defer cancel()
	for i := range a.Spec.Associations {
		ref := &a.Spec.Associations[i].Binding
		b := &v1alpha1.ComplianceBinding{}
		if err := c.Get(ctx, client.ObjectKey{Name: ref.Name}, b); err != nil {
			return apiError("ComplianceBinding "+ref.Name, err, "read access to compliancebindings (for example konstapel-compliance-viewer)")
		}
		switch {
		case ref.UID == "":
			ref.UID = string(b.UID)
		case ref.UID != string(b.UID):
			return fmt.Errorf("ComplianceBinding %s now has UID %s, not %s: it was recreated; associations never move to a replacement, so review and update the manifest", ref.Name, b.UID, ref.UID)
		}
	}
	opts := []client.CreateOption{client.FieldValidation("Strict")}
	if dry {
		opts = append(opts, client.DryRunAll)
	}
	if err := c.Create(ctx, a, opts...); err != nil {
		return apiError("create EvidenceAttachment "+a.Name, err, "konstapel-evidence-attachment-registrar")
	}
	if dry {
		a.ManagedFields, a.UID, a.ResourceVersion, a.Generation = nil, "", "", 0
		a.CreationTimestamp = metav1.Time{}
		out, _ := yaml.Marshal(a)
		fmt.Fprintf(e.stdout, "# server-side dry run: nothing was created\n%s", out)
		return nil
	}
	fmt.Fprintf(e.stdout, "evidenceattachment/%s created\nuid: %s\nregisteredBy: %s\n", a.Name, a.UID, registrant(a))
	return nil
}

func emptyStatus(s v1alpha1.EvidenceAttachmentStatus) bool {
	return s.ObservedGeneration == 0 && len(s.Associations) == 0 && s.Storage == nil && len(s.Conditions) == 0 &&
		s.Validity == nil && s.Content == nil && s.Withdrawal == nil
}

func registrant(a *v1alpha1.EvidenceAttachment) string {
	if a.Spec.RegisteredBy == nil {
		return "(not recorded: the registrant admission policy is not installed)"
	}
	return a.Spec.RegisteredBy.Username
}

// transferClient builds the TLS-only transfer client and reads the token.
func (e *evidenceCmd) transferClient() (*http.Client, string, *url.URL, error) {
	if e.server == "" || e.tokenFile == "" {
		return nil, "", nil, errors.New("--server and --token-file are required")
	}
	base, err := url.Parse(e.server)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, "", nil, fmt.Errorf("--server %q must be an https:// URL: bearer tokens and documents never cross the network unencrypted", e.server)
	}
	raw, err := os.ReadFile(e.tokenFile)
	if err != nil {
		return nil, "", nil, err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, "", nil, fmt.Errorf("%s is empty: create a token for the download service audience, for example kubectl create token SA --audience konstapel-download", e.tokenFile)
	}
	if e.http != nil {
		return e.http, token, base, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if e.caFile != "" {
		pem, err := os.ReadFile(e.caFile)
		if err != nil {
			return nil, "", nil, err
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, "", nil, fmt.Errorf("%s holds no PEM certificate", e.caFile)
		}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true},
		// Redirects would resend the token elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token, base, nil
}

// serviceError explains a download service answer.
func serviceError(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := strings.TrimSpace(string(b))
	hint := ""
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		hint = " (the token was not accepted: it must be valid and issued for the service's audience, konstapel-download by default)"
	case http.StatusForbidden:
		hint = map[string]string{
			"upload":   " (uploading needs konstapel-evidence-attachment-uploader: get on the record and create on evidenceattachments/upload; an unknown UID answers the same)",
			"download": " (downloading needs konstapel-evidence-attachment-downloader: get on the record and get on evidenceattachments/download; an unknown UID answers the same)",
		}[op]
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		hint = " (retry after " + resp.Header.Get("Retry-After") + "s; a retried upload converges on one commitment)"
	}
	return fmt.Errorf("%s failed: %s: %s%s", op, resp.Status, msg, hint)
}

func (e *evidenceCmd) upload(name, uid, path string) error {
	if uid == "" || path == "" {
		return errors.New("upload needs NAME, --uid UID and --file FILE")
	}
	hc, token, base, err := e.transferClient()
	if err != nil {
		return err
	}
	c, err := e.newClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	a, err := e.record(ctx, c, name, uid, "get on evidenceattachments (konstapel-evidence-attachment-uploader)")
	if err != nil {
		return err
	}
	if !a.DeletionTimestamp.IsZero() {
		return fmt.Errorf("EvidenceAttachment %s is withdrawn (being deleted) and accepts no upload; register a new record", name)
	}
	doc, err := fileDocument(path)
	if err != nil {
		return err
	}
	if want := attachments.Expected(a.Spec); doc != want {
		return fmt.Errorf("%s is %s (%d bytes), but %s registers %s (%d bytes): nothing was sent; a corrected document needs a new record", path, doc.SHA256, doc.Size, name, want.SHA256, want.Size)
	}
	if _, err = e.awaitPin(ctx, c, a); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, base.JoinPath("v1/evidenceattachments", uid, "upload").String(), f)
	req.ContentLength = doc.Size
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w (retrying is safe: an upload that committed returns that commitment)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serviceError("upload", resp)
	}
	var r download.UploadReceipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return fmt.Errorf("upload: unreadable receipt: %w", err)
	}
	if r.UID != uid || r.SHA256 != doc.SHA256 || r.Size != doc.Size {
		return fmt.Errorf("upload: the service answered for another document (%s %s)", r.UID, r.SHA256)
	}
	fmt.Fprintf(e.stdout, "evidenceattachment/%s committed\nuid: %s\ndocument: %s (%d bytes)\nuploader: %s\ncommittedAt: %s\nexpiresAt: %s (source retention %s)\n",
		name, r.UID, r.SHA256, r.Size, r.Uploader.Username, r.CommittedAt.UTC().Format(time.RFC3339), r.ExpiresAt.UTC().Format(time.RFC3339), r.Retention)
	fmt.Fprintln(e.stdout, "The controller records the commitment (DocumentCommitted=True) within about a minute. This attests storage and integrity only.")
	return nil
}

// awaitPin waits until the controller pinned the record's destination: the
// service accepts bytes only for a pinned record.
func (e *evidenceCmd) awaitPin(ctx context.Context, c client.Client, a *v1alpha1.EvidenceAttachment) (*v1alpha1.EvidenceAttachment, error) {
	deadline := time.Now().Add(e.pinWait)
	for a.Status.Storage == nil || a.Status.Storage.Destination == nil {
		if !time.Now().Before(deadline) {
			why := "no DocumentCommitted condition yet; is the controller running?"
			if cond := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionDocumentCommitted); cond != nil {
				why = cond.Reason + ": " + cond.Message
			}
			return nil, fmt.Errorf("EvidenceAttachment %s has no pinned storage destination yet (%s); nothing was sent", a.Name, why)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
		next, err := e.record(ctx, c, a.Name, string(a.UID), "get on evidenceattachments (konstapel-evidence-attachment-uploader)")
		if err != nil {
			return nil, err
		}
		a = next
	}
	return a, nil
}

func (e *evidenceCmd) download(name, uid, out string) error {
	if uid == "" || out == "" {
		return errors.New("download needs NAME, --uid UID and --output FILE")
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("%s exists; choose a new --output path", out)
	}
	hc, token, base, err := e.transferClient()
	if err != nil {
		return err
	}
	c, err := e.newClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	a, err := e.record(ctx, c, name, uid, "get on evidenceattachments (konstapel-evidence-attachment-downloader)")
	if err != nil {
		return err
	}
	want := attachments.Expected(a.Spec)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.JoinPath("v1/evidenceattachments", uid, "download").String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serviceError("download", resp)
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".konstapel-evidence-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, want.Size+1))
	if err != nil {
		return fmt.Errorf("download interrupted: %w; nothing was written", err)
	}
	sum := h.Sum(nil)
	got := attachments.Document{SHA256: "sha256:" + hex.EncodeToString(sum), Size: n}
	if got != want || resp.Header.Get("Repr-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":" {
		return fmt.Errorf("the received bytes (%s, %d bytes) are not %s's registered document (%s, %d bytes); nothing was written", got.SHA256, got.Size, name, want.SHA256, want.Size)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Link, not rename: an output that appeared meanwhile is never replaced.
	if err := os.Link(tmp.Name(), out); err != nil {
		return err
	}
	withdrawn := ""
	if resp.Header.Get("X-Konstapel-Withdrawn") == "true" {
		withdrawn = " (the record is withdrawn; its source is retained until expiresAt)"
	}
	fmt.Fprintf(e.stdout, "wrote %s\ndocument: %s (%d bytes), verified against evidenceattachment/%s\ndeclared mediaType: %s\nvalidity: %s to %s\nexpiresAt: %s%s\n",
		out, got.SHA256, got.Size, name, a.Spec.Document.MediaType, a.Spec.Validity.ValidFrom.UTC().Format(time.RFC3339),
		a.Spec.Validity.ValidUntil.UTC().Format(time.RFC3339), resp.Header.Get("X-Konstapel-Expires-At"), withdrawn)
	return nil
}

func (e *evidenceCmd) status(name, uid, output string) error {
	c, err := e.newClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.requestTimeout)
	defer cancel()
	a, err := e.record(ctx, c, name, uid, "get on evidenceattachments (konstapel-evidence-attachment-reader)")
	if err != nil {
		return err
	}
	switch output {
	case "json":
		b, _ := json.MarshalIndent(map[string]any{"name": a.Name, "uid": a.UID, "withdrawn": !a.DeletionTimestamp.IsZero(), "spec": a.Spec, "status": a.Status}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
		return nil
	case "text":
	default:
		return fmt.Errorf("-o %q: use text or json", output)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "Name:          %s\nUID:           %s\n", a.Name, a.UID)
	switch {
	case a.Status.Withdrawal != nil:
		fmt.Fprintf(&b, "Withdrawn:     %s (never in new coverage; a committed source is retained until its expiry)\n", a.Status.Withdrawal.WithdrawnAt.UTC().Format(time.RFC3339))
	case !a.DeletionTimestamp.IsZero():
		fmt.Fprintf(&b, "Withdrawn:     %s (never in new coverage; a committed source is retained until its expiry)\n", a.DeletionTimestamp.UTC().Format(time.RFC3339))
	}
	d := a.Spec.Document
	fmt.Fprintf(&b, "Document:      %s (%s, %d bytes, %s)\n", d.Title, d.MediaType, d.Size, d.SHA256)
	fmt.Fprintf(&b, "Validity:      %s to %s (declared)", a.Spec.Validity.ValidFrom.UTC().Format(time.RFC3339), a.Spec.Validity.ValidUntil.UTC().Format(time.RFC3339))
	if v := a.Status.Validity; v != nil {
		fmt.Fprintf(&b, "; %s", v.State)
		if v.NextTransition != nil {
			fmt.Fprintf(&b, " until %s", v.NextTransition.UTC().Format(time.RFC3339))
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Source:        %s (declared, not authenticated)\n", a.Spec.Source.Issuer)
	if a.Spec.Source.URL != "" {
		fmt.Fprintf(&b, "Source URL:    %s (informational; never fetched)\n", a.Spec.Source.URL)
	}
	fmt.Fprintf(&b, "Registered by: %s\n", registrant(a))
	for i, as := range a.Spec.Associations {
		state := "Pending"
		if i < len(a.Status.Associations) {
			s := a.Status.Associations[i]
			state = string(s.State) + "/" + s.Reason
		}
		ids := make([]string, 0, len(as.Controls))
		for _, ctl := range as.Controls {
			ids = append(ids, ctl.ID)
		}
		fmt.Fprintf(&b, "Association:   binding %s (uid %s) controls %s: %s\n", as.Binding.Name, as.Binding.UID, strings.Join(ids, ","), state)
	}
	if st := a.Status.Storage; st != nil && st.Destination != nil {
		fmt.Fprintf(&b, "Destination:   %s (uid %s)\n", st.Destination.Name, st.Destination.UID)
		if cm := st.Commitment; cm != nil {
			fmt.Fprintf(&b, "Committed:     %s by %s; source retained until %s (retention %s)\n", cm.CommittedAt.UTC().Format(time.RFC3339),
				cm.Uploader.Username, cm.ExpiresAt.UTC().Format(time.RFC3339), cm.Retention.Duration)
		}
		if cl := st.Cleanup; cl != nil {
			fmt.Fprintf(&b, "Cleanup:       %s %s\n", cl.State, cl.Message)
			if cl.Attempts > 0 && cl.LastAttempt != nil {
				fmt.Fprintf(&b, "               %d failed attempts, the last at %s\n", cl.Attempts, cl.LastAttempt.UTC().Format(time.RFC3339))
			}
		}
	}
	if c := a.Status.Content; c != nil {
		fmt.Fprintf(&b, "Content:       %s/%s: %s\n", c.State, c.Reason, c.Message)
	}
	for _, t := range []string{v1alpha1.ConditionAssociationsValid, v1alpha1.ConditionDocumentCommitted, v1alpha1.ConditionSourceRetained} {
		if cond := meta.FindStatusCondition(a.Status.Conditions, t); cond != nil {
			fmt.Fprintf(&b, "%-15s%s/%s: %s\n", t+":", cond.Status, cond.Reason, cond.Message)
		}
	}
	_, err = e.stdout.Write(b.Bytes())
	return err
}
