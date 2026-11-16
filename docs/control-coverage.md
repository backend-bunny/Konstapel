# Control coverage

Konstapel's control coverage view lists every control the selected compliance
baseline contains, with the authored technical checks available for each one
and whether the binding's `ComplianceProfile` selects them. Every control in
the baseline is listed. A missing check, a passing check, or an attached
document never adds a control to the list or removes one from it.

> **Status.** `internal/coverage` implements the baseline reader, the mapping
> join and the report model (`add-control-coverage-reporting` group 1). It does
> not yet read evidence. Assessment packages do not contain `coverage.json` or
> `coverage.txt` yet, and assessment status has no coverage summary. Joining
> collector observations, accepted risks and supporting documents, rendering,
> and the assessment integration are later groups of that change.

## Inputs

Coverage reads exactly one verified content handle:

| Handle | Constructor | Source |
| --- | --- | --- |
| Frozen bundle | `coverage.FromFrozen` | An assessment's frozen copy (`bundle.ReadFrozen` or the content owner's `Freeze`). |
| Cache entry | `coverage.FromDescriptor` | An integrity-checked cache entry's descriptor and payload. |
| Vendored tree | `coverage.FromVendored` | The image's `content/` tree. Its digest is the sha256 of `content/SHA256SUMS` and must equal the pinned digest. |

The reader only opens files listed in the handle's inventory, and it checks
each file against its recorded digest again before use. Imports must resolve
inside that set of files and are never fetched. The vendored `SHA256SUMS`
does not list the authored component definitions. A vendored handle therefore
resolves the baseline when the caller names the profile (`Options.Profile`),
but its mappings are unresolved.

The caller supplies the controller's own trusted OSCAL schemas
(`Options.Schemas`, keyed by version), never the copy inside the bundle.
Before decoding any document, the reader checks that:

- no JSON key repeats;
- the document has a single OSCAL root;
- its `oscal-version` matches the version the content declares for it;
- it is valid against the trusted schema for that version.

The supported versions are 1.1.3 (authored C2P component definitions) and
1.2.3 (the official NIST catalog and profile). The reader decodes each
document at its own version, never through an older export model, so it
does not silently drop selection or statement semantics.

## Supported profile resolution

The baseline is the content's single declared profile entry point, or the one
named in `Options.Profile`. The supported semantics are versioned as
`konstapel.io/oscal-profile-selection/v1` (`coverage.Semantics`, recorded in
every report):

- **Imports.** A profile can import a catalog or another profile inside the
  content. An import is either a relative `href` or `#uuid`. A `#uuid` names a
  back-matter resource, which must have exactly one JSON `rlink` that resolves
  to an inventoried file. Remote links and links to other formats are ignored
  and never fetched.
- **Selection.** Use `include-all`, or `include-controls` by `with-ids`, with
  `with-child-controls` set to `yes` or `no`. `exclude-controls` works by
  `with-ids`. If an import of another profile selects a control, that profile
  must make the control available.
- **Merge.** `as-is`, `flat` or no merge, with combine `use-first` or `keep`.
  The inventory is a set of catalog control IDs, so structuring directives
  do not change which controls are in it.
- **One catalog.** Every import in the chain must resolve to the same
  catalog (by digest).

Anything else makes the inventory **unresolved**. That covers `matching`
selection patterns, `custom` merge, combine `merge`, any `modify` (`alters` or
`set-parameters`), imports of other models, import cycles, and chains deeper
than 8 profiles. An unresolved report lists no controls, only the documents it
read and coded limitations. It never falls back to the whole catalog, the
mapped subset, or a zero-control success.

### Identity

- **Controls.** Every control is qualified by the digest of its catalog. A
  report has one catalog (`inventory.catalog`), so a row's `id` together with
  that digest is the control's identity. An ID from another catalog revision is
  never attributed to a control in this baseline.
- **Enhancements.** Selected enhancements keep their own IDs, with a `parent`
  reference. The reader indexes controls recursively under catalog groups, and
  `groups` lists the enclosing groups, outermost first. The catalog defines
  these groups, for example NIST families; the model assumes no framework.
- **Statements.** A control's statements are its `statement` part and the
  nested `item` parts. Membership is checked within the referenced control,
  not against every ID in the catalog. Mapping `ac-6` to `cm-6_smt.b` is
  rejected even though `cm-6_smt.b` exists.
- **Duplicates.** If the profile selects the same control more than once
  (repeated `with-ids`, or across imports), the control counts once and a
  `DuplicateSelection` notice is recorded.

## Mappings and coverage states

The reader takes authored mappings from every declared component definition,
following the C2P convention:

- Software components declare rule sets: `Rule_Id` with a `Rule_Description`,
  optionally with `Parameter_Id` declarations, grouped by `remarks`.
- Implemented requirements map rules (`Rule_Id` props) to statements or, at
  requirement level, to the whole requirement.
- A validation component declares each rule's `Check_Id`.

A rule is joined to its logical policy through the bundle descriptor's checks.
Joining never assumes that the rule ID, policy name and validation index are
interchangeable. A control-implementation `source` must resolve to the
baseline's catalog, profile, or an imported profile.

Each check under a control has a selection state:

| Check state | Meaning |
| --- | --- |
| `selected` | The profile selects the check's policy. Its observations, joined in a later group, are partial technical evidence within the authored limits. |
| `unselected` | The check is available in the content, but the profile omits its policy. Nothing is evaluated. |
| `unresolved` | The mapping cannot be trusted, for example because of a wrong-control statement, an undeclared rule or check, an unknown parameter, or a selection that pins other content. |

Each control has an `automation` state:

| Control state | Meaning |
| --- | --- |
| `none` | No authored technical mapping targets the control. It has no automated assessment, and the state is neither a pass nor "not applicable". |
| `unselected` | Mappings exist, but none of their checks is selected. |
| `partial` | At least one selected check is mapped. Coverage is bounded by each rule's and statement's authored description. |
| `unknown` | A mapping for the control is unresolved, or the mapping documents themselves could not be read. In either case neither `none` nor `partial` can be claimed. |

There is no `full` state and no count or percentage of satisfied controls.
Passing checks, or every selected check passing, never mark a control, a
statement or the baseline satisfied. Some mappings are not attributed and
leave the controls they name unchanged. That happens when a mapping names a
control the catalog has but the baseline does not select
(`MappingControlNotSelected`), a control the catalog does not have
(`MappingControlUnknown`), or a control in another catalog
(`MappingCatalogMismatch`). Each case appears as a report limitation.

### Parameters

The report keeps three kinds of parameters apart:

| Field | What it is |
| --- | --- |
| Control `parameters` | The control's OSCAL parameters (organization-defined parameters) as the profile resolves them. The supported semantics forbid `modify`, so these are the catalog's own parameters. |
| Check `ruleParameters` and `oscalParameters` | Authored values in the component definition. A `set-parameter` naming a rule's `Parameter_Id` configures that rule. One naming an OSCAL parameter of the control is an authored setting of that parameter. Any other name is `ParameterUnresolved`. |
| Check `policyParameters` | The `ComplianceProfile`'s engine settings for a selected policy. |

`policyParameters` hold engine configuration, never values of the control's
OSCAL parameters, and are never matched to them. A policy parameter
contributes to a control parameter only through an authored mapping in the
component definition.

## Limitations

Every limitation has a `code`, an optional `document` and `subject`, and a
message. A **blocking** limitation makes the thing it qualifies unresolved:
the inventory, the mapping set, or one check. A non-blocking limitation
records a deduplication or a mapping that was not attributed.

| Area | Codes |
| --- | --- |
| Documents | `DocumentUnavailable`, `DocumentInvalid`, `SchemaVersionUnsupported`, `SchemaVersionMismatch` |
| Profile | `ProfileNotDeclared`, `ProfileAmbiguous`, `ImportUnresolved`, `ImportExternal`, `ImportOutsideContent`, `ImportAmbiguous`, `ImportCycle`, `ImportDepth`, `SemanticsUnsupported`, `SelectionNotInSource`, `MultipleCatalogs`, `DuplicateCatalogID`, `EmptySelection`, `DuplicateSelection` (notice) |
| Mappings | `MappingSourceUnresolved`, `MappingCatalogMismatch` (notice), `MappingControlUnknown` (notice), `MappingControlNotSelected` (notice), `DuplicateMapping` (notice), `StatementNotInControl`, `RuleUndeclared`, `RuleNotInContent`, `CheckUndeclared`, `ParameterUnresolved` |
| Selection | `SelectionContentMismatch`, `PolicyNotInContent` |

## Examples: the pinned Moderate inventory

The blocks below are regenerated by `TestControlCoverageDocExamples` in
`internal/coverage` from the shipped bundles. If the pinned content changes,
the test fails until this page is updated. To print the current blocks, run:

```sh
KONSTAPEL_UPDATE_DOCS=1 devbox run -- go test ./internal/coverage -run TestControlCoverageDocExamples -v
```

The Moderate profile selects every one of the 287 controls below, whichever
policies a profile selects. The 18 physical and environmental (`pe`) controls
have no technical mapping. They stay in the inventory with `none`; they do not
disappear and are not counted as passing.

<!-- coverage-inventory:begin -->
```
profile  content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json
         Electronic (OSCAL) Version of NIST Special Publication 800-53 Revision 5.2.0 MODERATE IMPACT BASELINE
         OSCAL 1.2.3, sha256:e3a0f11237cfaac24dfcf1586e07683f17423757fd84208deb33196b12e8f590
catalog  content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
         OSCAL 1.2.3, sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb
selected 287 controls (177 base controls, 110 enhancements) in 18 groups, 987 statement parts
physical (pe) 18: pe-1=none pe-2=none pe-3=none pe-4=none pe-5=none pe-6=none pe-6.1=none pe-8=none pe-9=none pe-10=none pe-11=none pe-12=none pe-13=none pe-13.1=none pe-14=none pe-15=none pe-16=none pe-17=none

konstapel-privileged-containers, profile selects disallow-privileged-containers
  partial    ac-6
  none       286 controls

konstapel-linux-hardening, profile selects disallow-privilege-escalation
  partial    ac-6, cm-6
  unselected cm-7
  none       284 controls
```
<!-- coverage-inventory:end -->

The `ac-6` row of the hardening example is shown below, abridged to two of its
four mapped checks. One check is selected and one is not. The row is
`partial`, and each check carries the authored limit of what it evidences. The
row does not claim AC-6 or the Moderate baseline is satisfied. AC-6 has no
OSCAL parameters, so the row has no `parameters` field. The selected policy
has no profile parameters, so the check has no `policyParameters` field.

<!-- coverage-row:begin -->
```
{
  "id": "ac-6",
  "label": "AC-6",
  "title": "Least Privilege",
  "class": "SP800-53",
  "groups": [
    {
      "id": "ac",
      "title": "Access Control"
    }
  ],
  "statements": [
    "ac-6_smt"
  ],
  "automation": "partial",
  "checks": [
    {
      "ruleId": "disallow-privilege-escalation",
      "checkId": "disallow-privilege-escalation",
      "policy": "disallow-privilege-escalation",
      "policyDigest": "sha256:e24055b5...",
      "selection": "selected",
      "description": "Partial AC-6 and CM-6 technical evidence: requires every container to declare allowPrivilegeEscalation false, a declared privilege and configuration restriction. Does not observe privilege transitions at runtime, assess authorization or organizational procedures, or establish full AC-6/CM-6/Moderate satisfaction.",
      "checkDescription": "disallow-privilege-escalation",
      "requirementDescription": "Partial technical evidence only; each mapped check is a separate, bounded observation.",
      "statements": [
        {
          "id": "ac-6_smt",
          "description": "Least-privilege configuration evidence for workload containers; partial coverage only."
        }
      ],
      "definitions": [
        "content/linux-hardening/component-definition.json"
      ]
    },
    {
      "ruleId": "require-run-as-nonroot",
      "checkId": "require-run-as-nonroot",
      "policy": "require-run-as-nonroot",
      "policyDigest": "sha256:17af842e...",
      "selection": "unselected",
      "description": "Partial AC-6 and CM-6 technical evidence: requires every container to request non-root execution (runAsNonRoot true, set or inherited; user namespaces are no exemption). Does not observe the UID a process runs as, and does not establish full AC-6/CM-6/Moderate satisfaction.",
      "checkDescription": "require-run-as-nonroot",
      "requirementDescription": "Partial technical evidence only; each mapped check is a separate, bounded observation.",
      "statements": [
        {
          "id": "ac-6_smt",
          "description": "Least-privilege configuration evidence for workload containers; partial coverage only."
        }
      ],
      "definitions": [
        "content/linux-hardening/component-definition.json"
      ]
    }
  ]
}
```
<!-- coverage-row:end -->

## Framework neutrality

Nothing in the model is specific to NIST. Identifiers, labels, groups and
statement IDs come from the catalog, and coverage states come from the
authored mappings. The test suite resolves a small non-NIST fixture with the
same code. That fixture's controls look like `op1` and `op1.e1`, its statements
like `op1-req-a`, and it uses a two-level profile chain and a C2P component
definition. The fixture shows that the model works for another catalog. It is
not a production adapter for another framework. NIST SP 800-53 Rev. 5 Moderate
is the first real content.
