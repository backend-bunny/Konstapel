# Spec Delta

## ADDED Requirements

### Requirement: Status records source-evaluation and scheduling watermarks

Assessment status SHALL record the source evaluation time of the oldest
attributable observation in current evidence and in each closed run's summary,
taken from the evaluated results and never from collection, upload or
report-update times, and absent when no observation is attributable.
Binding schedule status SHALL record the earliest scheduled time, including
missed times coalesced into a later run, whose obligation has not yet been met
by a scheduled run that closed with an assessment export, complete or
incomplete. Diagnostic exports, lost captures, deleted runs, manual runs and
namespace requests SHALL NOT meet that obligation; a later scheduled run that
closes with an assessment export SHALL meet every earlier obligation it caught
up on while missed ranges remain recorded. Interval changes SHALL NOT discard an
outstanding obligation. Both fields SHALL be additive, absent when they do not
apply, and SHALL NOT change scheduling, enforcement or evidence semantics.

#### Scenario: Current evidence ages

- **WHEN** current evidence contains attributable observations evaluated at different times
- **THEN** status records the earliest of those source evaluation times
- **AND** the evidence expiry remains that time plus the evidence-age limit used at evaluation

#### Scenario: A scheduled run fails to export

- **WHEN** a scheduled run closes as a diagnostic or loses its capture
- **THEN** its scheduled time remains the earliest outstanding obligation
- **AND** the next scheduled run starts on the unchanged cadence

#### Scenario: A catch-up run closes with an incomplete assessment

- **WHEN** missed scheduled times were coalesced into one run that closes with an incomplete assessment export
- **THEN** no obligation up to that run's scheduled time remains outstanding
- **AND** the missed range stays recorded as not assessed
