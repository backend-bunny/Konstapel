# Supporting evidence

Some controls in the selected baseline, such as datacenter physical security
(PE-3), can't be checked by workload policies. Platform operators can register
supporting documents for those controls as `EvidenceAttachment` records
(`compliance.erenius.io/v1alpha1`, cluster-scoped). An attachment is
supporting material. It has no verdict field, and it never changes technical
findings, expected checks, enforcement or risk acceptance.

**Status.** This is the `add-supporting-evidence-attachments` change, task
group 1. The following are implemented:

- the API;
- authenticated registrant attribution;
- association validation by the controller;
- the retention finalizer;
- the platform roles.

Document upload, storage, download, the `konstapel evidence` CLI, validity
and availability status, and inclusion in assessment packages come in later
task groups. Until then, a record describes a document and its associations,
but Konstapel holds no bytes for it.

Platform operators manage attachments. Application-team attachments are
future work, and no namespace role can register or read them.

## Registering a document

The [example](examples/supporting-evidence/attachment-datacenter.yaml)
registers one audit report for PE-3 of two bindings:

```yaml
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata:
  name: dc-north-physical-access-2026
spec:
  document:
    title: DC North physical access control audit 2026
    mediaType: application/pdf
    size: 482113
    sha256: sha256:9f2b…2a10
  source:
    issuer: Example Audit AB on behalf of the DC North facility operator
    url: https://audits.example.com/reports/dc-north-2026
  validity:
    validFrom: "2026-01-01T00:00:00Z"
    validUntil: "2027-01-01T00:00:00Z"
  scope:
    description: DC North halls A and B, which host every node of this cluster.
  associations:
    - binding: {name: baseline-audit, uid: 0b6c1f0e-…}
      catalogDigest: sha256:64ca6b41…5eeb
      controls:
        - id: pe-3
          statements: [pe-3_smt.a, pe-3_smt.b]
        - id: pe-6
    - binding: {name: payments-deny, uid: 6a2e9d47-…}
      catalogDigest: sha256:64ca6b41…5eeb
      controls:
        - id: pe-3
```

Collect the exact identities before you register:

```sh
kubectl get compliancebinding baseline-audit -o jsonpath='{.metadata.uid}'
sha256sum dc-north-2026.pdf          # spec.document.sha256 is "sha256:<hex>"
stat -c %s dc-north-2026.pdf         # spec.document.size
kubectl create -f attachment.yaml    # as a konstapel-evidence-attachment-registrar subject
```

`catalogDigest` is the SHA-256 of the OSCAL catalog file in the bundle the
binding's profile pins, at
`content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json`.
For the vendored NIST SP 800-53 Rev 5 catalog it is
`sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb`.
If the binding resolves a different catalog, its status shows that catalog as
`observedCatalogDigest`. This version has no `konstapel evidence` command to
look these values up (task 3.3).

| Field | Meaning | Checked |
| --- | --- | --- |
| `document.title`, `mediaType` | Descriptive. The media type is lowercase `type/subtype` with no parameters. Downloads are always passive attachments. | non-blank title; media-type syntax |
| `document.size`, `sha256` | The exact bytes the transfer service will accept | 1 byte to 1 GiB (the transfer service's own default limit is lower, 32 MiB); `sha256:` + 64 lowercase hex |
| `source.issuer`, `source.url` | Declared provenance. Konstapel never fetches the URL and never authenticates the issuer. | non-blank; `http(s)://` URL |
| `validity.validFrom`, `validUntil` | The declared coverage window, `validFrom <= T < validUntil`. Upload time never changes it. | both required RFC 3339 timestamps; `validFrom < validUntil` |
| `scope.description` | The platform's statement of the facility or system covered | non-blank |
| `associations[]` | 1–32 associations, each naming an exact binding (name and UID), a catalog digest, and 1–64 controls with optional statement parts | structure at the API; meaning by the controller (below); a binding UID at most once |
| `registeredBy` | Set by admission; don't supply it | see [Attribution](#attribution) |

The CRD prunes unknown fields, and `kubectl create` (strict field validation)
rejects them. The record can't carry document bytes, credentials, storage
locations or verdicts.

## Immutable records and replacement

Every `spec` field is fixed when the record is created. The API server rejects
any change, even from a cluster administrator:

```text
spec: Invalid value: "object": spec is immutable; register a new EvidenceAttachment
```

Each of these needs a new record (and, once upload exists, a new upload):

- a corrected document;
- a different validity period;
- a different catalog mapping;
- another binding.

Delete the old record to withdraw it. A record never acquires a new evidence
revision in place, and re-registering the same document can't make an expired
period current.

Labels, annotations and the controller's finalizer are not evidence. You can
change labels and annotations.

## Attribution

The `konstapel-evidence-attachment-registrant` admission policies
(`config/admission/evidence-attachment-registrant.yaml`) set
`spec.registeredBy` from the API server's authenticated user (username and
UID) on create. A value that names someone else is overwritten, and the
validating policy fails closed if the stored value doesn't match the caller.
Combined with spec immutability, nobody can later rewrite the registrant.
The record's `metadata.creationTimestamp` is the API server's submission time.

Three identities stay distinct:

| Identity | Recorded by | Authenticated |
| --- | --- | --- |
| Registrant (`spec.registeredBy`) | admission, on create | yes |
| Uploader | the transfer service, in the storage receipt (task group 3) | yes |
| Declared source (`spec.source`) | the registrant | no; it is a claim |

## Associations

The controller validates every association before it applies. The result is
shown in `status.associations[]` (in spec order) and the `AssociationsValid`
condition:

| State | Reason | When |
| --- | --- | --- |
| `Valid` | `Valid` | The binding exists with the registered UID. It has resolved its current spec and profile revision. That revision's verified bundle has the registered catalog digest, and its Moderate baseline profile selects every control. Every statement is a `statement` or `item` part of its own control. |
| `Pending` | `BindingUnresolved` | The binding hasn't resolved its current spec or profile revision yet. Rechecked every minute and on binding changes. |
| `Pending` | `BaselineUnavailable` | The bundle content can't be read. The controller reads vendored content of its own digest, or a frozen copy of verified OCI content. Other content is never substituted. |
| `Mismatched` | `BindingNotFound` | No binding has that name. |
| `Mismatched` | `BindingReplaced` | The binding was recreated, so its UID changed. The association is never inherited. |
| `Mismatched` | `CatalogMismatch` | The binding now resolves a different catalog revision. |
| `Mismatched` | `ControlNotInBaseline` | A control isn't in the binding's selected baseline. |
| `Mismatched` | `StatementNotInControl` | A statement isn't one of its control's statement parts, for example `pe-2_smt.a` under `pe-3`, or a guidance part. |

`AssociationsValid` is `True` when every association is Valid, `False` when
any is Mismatched, and `Unknown` while any is Pending. A mismatch is final for
that record. To correct it, register a new record.

Some binding edits keep associations valid:

- reporting-only edits (`spec.assessment`);
- a new profile revision with the same catalog and controls.

Associations can target physical or organizational controls that have no
technical mapping. One record can support several explicitly named bindings
in this cluster. Konstapel doesn't infer datacenter membership from labels,
and records are never imported across clusters.

Associating a document with a binding covers that binding's namespace scope
for reporting. It gives the binding's teams no access to the document or its
metadata.

## Withdrawal and retention

Deleting a record withdraws it from new current evidence immediately. The
controller adds the `compliance.erenius.io/evidence-attachment-retention`
finalizer to every record. Later task groups (2 and 4) will use it to keep
the record and its storage ownership until the source document's fixed
retention expiry, which is `max(committedAt, validUntil) + retention`, 2160h
by default. In this version no record owns stored bytes, so the controller
releases the finalizer as soon as the record is deleted. If the controller is
not running, deleted records wait for it.

The finalizer is the only lifecycle link. Attachments have no owner
references, so deleting a binding or namespace never deletes an attachment.

## Authority

All roles are ClusterRoles in `config/rbac/evidence-attachments.yaml`, shipped
in the runtime chart. None is aggregated into the built-in `admin`, `edit` or
`view` roles. Bind them with ClusterRoleBindings to platform subjects only.

| Role | Grants | Purpose |
| --- | --- | --- |
| `konstapel-evidence-attachment-registrar` | `evidenceattachments`: get, list, watch, create, delete; `status`: get | Register and withdraw records. There is no update or patch: the spec is immutable. |
| `konstapel-evidence-attachment-uploader` | `evidenceattachments`: get; `evidenceattachments/upload`: create | Upload a registered record's bytes (transfer service, task group 3) |
| `konstapel-evidence-attachment-reader` | `evidenceattachments` and `status`: get, list, watch | Read metadata and status, never bytes |
| `konstapel-evidence-attachment-downloader` | `evidenceattachments`: get; `evidenceattachments/download`: get | Cluster-wide document read through the transfer service. There are no per-document ACLs. |
| `konstapel-controller` (generated) | `evidenceattachments`: get, list, watch, update, patch; `status`: get, update, patch; `finalizers`: update | Validation, status and the retention finalizer |

`evidenceattachments/upload` and `/download` are authorization attributes
that the transfer service will check with SubjectAccessReview. They are not
CRD subresources, and the API server doesn't serve them. No other shipped role
grants anything on `evidenceattachments`. That includes the assessment
requester and exception editor (namespace roles), the compliance admin and
viewer, and the assessment operator. Only the controller writes status.

To check what a subject can do:

```sh
kubectl auth can-i create evidenceattachments --as=platform-registrar          # yes for registrars only
kubectl auth can-i create evidenceattachments --subresource=upload --as=u      # yes for uploaders only
kubectl auth can-i get evidenceattachments --subresource=download --as=d       # yes for downloaders only
kubectl auth can-i get evidenceattachments --as=system:serviceaccount:team-a:dev   # no
```

`TestAttachmentAuthorityMatrix` checks this matrix statically against every
shipped role. `TestLiveEvidenceAttachmentAPI` (acceptance group `admission`)
checks the same probes with SubjectAccessReview against a real API server.
The live test also checks:

- the published example's validation;
- strict field validation and immutability;
- forged-registrant replacement;
- controller association states for shared, foreign-statement, wrong-catalog,
  reporting-only-edit and recreated-binding cases;
- withdrawal.
