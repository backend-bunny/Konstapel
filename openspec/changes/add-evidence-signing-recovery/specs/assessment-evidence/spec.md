# Spec Delta

## MODIFIED Requirements

### Requirement: Per-binding retention is fixed at publication

Konstapel SHALL apply the binding's configured retention, defaulting to 2160h
(90 days), to scheduled and on-demand packages. The first successful publication
SHALL record its effective retention and a fixed expiry measured from publication.
Later retention changes SHALL apply only to new publications and SHALL NOT
shorten or extend an already published package's expiry. A publication recovered
after a signing failure SHALL keep the expiry recorded at that failure.

#### Scenario: Shorten retention after publication

- **WHEN** a binding changes retention from 90 days to 30 days
- **THEN** existing published packages retain their recorded expiry
- **AND** subsequent publications use the new duration

#### Scenario: Retry an old publication under changed settings

- **WHEN** an already committed publication is recovered after retention changes
- **THEN** its original expiry is preserved rather than recalculated from retry time

#### Scenario: Publish evidence through signing recovery

- **WHEN** a run that failed signing is published later by an administrator's recovery request
- **THEN** its expiry stays the closure time plus the retention recorded at closure
- **AND** it is not measured from the recovered commit time
