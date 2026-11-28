# Changelog

## [0.4.0](https://github.com/backend-bunny/Konstapel/compare/v0.3.0...v0.4.0) (2026-11-28)


### Features

* **api:** AssessmentProvider registration API and RBAC (2.1) ([#383](https://github.com/backend-bunny/Konstapel/issues/383)) ([f75ccc8](https://github.com/backend-bunny/Konstapel/commit/f75ccc86050da9e9478e04d1b1af134f6e701a92))
* **bundles:** separately versioned OCI revision for split hardening checks (1.3) ([#404](https://github.com/backend-bunny/Konstapel/issues/404)) ([601a8a4](https://github.com/backend-bunny/Konstapel/commit/601a8a459ef7ba37e8592386298d7cf2a9b13d92))
* **chart:** opt-in external provider client configuration (2.3) ([#386](https://github.com/backend-bunny/Konstapel/issues/386)) ([81e9e53](https://github.com/backend-bunny/Konstapel/commit/81e9e532abdd386b3d52076242a7db0d99488f58))
* **chart:** reference external provider chart (5.1) ([#392](https://github.com/backend-bunny/Konstapel/issues/392)) ([b829cd1](https://github.com/backend-bunny/Konstapel/commit/b829cd1e67d9ce7082e3e74f42a582883e8d8dfa))
* **charts:** opt-in exception admission webhooks and gated revocation ([#356](https://github.com/backend-bunny/Konstapel/issues/356)) ([1ef9794](https://github.com/backend-bunny/Konstapel/commit/1ef9794ad5a3459d20645861aed48c79f55afbef))
* **collector:** connect provider captures to run content (3.2) ([#360](https://github.com/backend-bunny/Konstapel/issues/360)) ([53c7d47](https://github.com/backend-bunny/Konstapel/commit/53c7d4755228af7f034fce2aff10d3025bac0b9f))
* **collector:** provider-discriminated capture boundary (3.1) ([#357](https://github.com/backend-bunny/Konstapel/issues/357)) ([221a5b5](https://github.com/backend-bunny/Konstapel/commit/221a5b581f4d2c321cc33e3ad4f9d58178b53168))
* **collector:** record provider selection changes observed after freeze ([#397](https://github.com/backend-bunny/Konstapel/issues/397)) ([382df84](https://github.com/backend-bunny/Konstapel/commit/382df8460f8295f3cb47cb201a1f56f7d99526c0))
* **collector:** shared namespace projection check (3.3) ([#365](https://github.com/backend-bunny/Konstapel/issues/365)) ([747ee66](https://github.com/backend-bunny/Konstapel/commit/747ee66069044c9908c21f34e1550384adc80c52))
* **content:** single-validation hardening variants (1.1-1.2) ([#380](https://github.com/backend-bunny/Konstapel/issues/380)) ([c67e1fe](https://github.com/backend-bunny/Konstapel/commit/c67e1fe1349f0d60d8a10648a5add3ee25c1b9c0))
* **provider:** bound adapter collection on the host (2.3, 2.4) ([#348](https://github.com/backend-bunny/Konstapel/issues/348)) ([17149c5](https://github.com/backend-bunny/Konstapel/commit/17149c51ef901d02484fc10a60d24fb8cc5b491f))
* **provider:** derive provider availability from descriptors (2.2) ([#347](https://github.com/backend-bunny/Konstapel/issues/347)) ([0da2b44](https://github.com/backend-bunny/Konstapel/commit/0da2b44c2354b821cc388d6e0e8d448f4260d4fc))
* **provider:** installed-provider registry and conformance harness ([#344](https://github.com/backend-bunny/Konstapel/issues/344)) ([1c54f63](https://github.com/backend-bunny/Konstapel/commit/1c54f633bb916675042f80dae28964a7fa39fada))
* **provider:** Kyverno inventory and collection adapters (2.1) ([#346](https://github.com/backend-bunny/Konstapel/issues/346)) ([5f1c19f](https://github.com/backend-bunny/Konstapel/commit/5f1c19f2b4685a4c0922e1a5840b7e59dfd15af9))
* **provider:** mutual TLS transport for external providers (1.2) ([#382](https://github.com/backend-bunny/Konstapel/issues/382)) ([bffca04](https://github.com/backend-bunny/Konstapel/commit/bffca045bb1c971b156af90bd2d18b44385ffebf))
* **provider:** protocol revision 2 inventory, capture identity and collection seam (3.1.1-3.1.3) ([#398](https://github.com/backend-bunny/Konstapel/issues/398)) ([1f6e9a5](https://github.com/backend-bunny/Konstapel/commit/1f6e9a5e1d70cb1121db442ef151cf9b64138c87))
* **provider:** pure evaluators with explicit time (4.1) ([#368](https://github.com/backend-bunny/Konstapel/issues/368)) ([399ce04](https://github.com/backend-bunny/Konstapel/commit/399ce0499d47bdf01047dd86710dc219981cae91))
* **provider:** reference provider signing, SBOM and provenance (5.2) ([#393](https://github.com/backend-bunny/Konstapel/issues/393)) ([0ddcaa5](https://github.com/backend-bunny/Konstapel/commit/0ddcaa58d50abe3744705732b46d0360994a66b6))
* **provider:** registered external provider selection (2.2) ([#385](https://github.com/backend-bunny/Konstapel/issues/385)) ([12f49ba](https://github.com/backend-bunny/Konstapel/commit/12f49baa1456e7b5499f2946ed567588a89ed30c))
* **provider:** separate evaluator endpoint with its own identity (2.4) ([#399](https://github.com/backend-bunny/Konstapel/issues/399)) ([36e5d45](https://github.com/backend-bunny/Konstapel/commit/36e5d457a01b51f095704f41a34e3aa1b1bc3488))
* **provider:** shared C2P conversion of frozen snapshots (4.2) ([#370](https://github.com/backend-bunny/Konstapel/issues/370)) ([6670503](https://github.com/backend-bunny/Konstapel/commit/667050360a11f873716d0f1a305924515a8a3ef7))
* **provider:** versioned external provider protocol (1.1) ([#381](https://github.com/backend-bunny/Konstapel/issues/381)) ([1e5485e](https://github.com/backend-bunny/Konstapel/commit/1e5485eaae6e7bbd9c96fa7766a727a3ad20c252))
* **signing:** bounded recovery attempt and recorded success (recovery 2.5, 2.6) ([#371](https://github.com/backend-bunny/Konstapel/issues/371)) ([bc0d485](https://github.com/backend-bunny/Konstapel/commit/bc0d4853092fba7de7d85e7ed3e5a1b66d461353))
* **signing:** evidence signing request API, admission, and roles (recovery 1.1-1.4) ([#355](https://github.com/backend-bunny/Konstapel/issues/355)) ([2333cf0](https://github.com/backend-bunny/Konstapel/commit/2333cf0a383aa91329f7742320504ebbe0875e1f))
* **signing:** per-run recovery claim and manager wiring (recovery 2.3) ([#364](https://github.com/backend-bunny/Konstapel/issues/364)) ([edbde0b](https://github.com/backend-bunny/Konstapel/commit/edbde0b81694e590e8813711b06301b1fecd869e))
* **signing:** recovery attempt via signingRequirement (recovery 2.4) ([#367](https://github.com/backend-bunny/Konstapel/issues/367)) ([23efdb6](https://github.com/backend-bunny/Konstapel/commit/23efdb6699b3190a0c6b1bc01ae8c6878eaff5f9))
* **signing:** recovery request gauge and events (recovery 3.1) ([#374](https://github.com/backend-bunny/Konstapel/issues/374)) ([a169f53](https://github.com/backend-bunny/Konstapel/commit/a169f5381d0d29858e2065e4ab58c1c4fb8b58a0))
* **signing:** recovery retention bound and eligibility (recovery 2.1-2.2) ([#361](https://github.com/backend-bunny/Konstapel/issues/361)) ([94f8934](https://github.com/backend-bunny/Konstapel/commit/94f89341a0f43fb70f267de35c8fddc620888711))
* **targeting:** bounded Kyverno readiness diagnostics (1.1-1.2) ([#372](https://github.com/backend-bunny/Konstapel/issues/372)) ([4969f3a](https://github.com/backend-bunny/Konstapel/commit/4969f3a18049b80e8118ac9dc4d518c9ea89c301))
* **targeting:** bounded readiness recheck for owned Kyverno policies (3.1-3.2) ([#396](https://github.com/backend-bunny/Konstapel/issues/396)) ([896029a](https://github.com/backend-bunny/Konstapel/commit/896029aca9eb0e943ca5e6326ddec09e04e49925)), closes [#358](https://github.com/backend-bunny/Konstapel/issues/358)


### Bug Fixes

* **admission:** requester policies overwrite requestedBy wholesale ([#390](https://github.com/backend-bunny/Konstapel/issues/390)) ([8dc1f83](https://github.com/backend-bunny/Konstapel/commit/8dc1f836454dae8a3876ed172837ca1f5c84cc3d))
* **bundles:** require signature payload in bundle verification docs; guard verifier ([#407](https://github.com/backend-bunny/Konstapel/issues/407)) ([a771fbc](https://github.com/backend-bunny/Konstapel/commit/a771fbcf5de8ff719de9e249bda340d0375ca554))
* **charts:** require signature payload when verifying chart artifacts ([#403](https://github.com/backend-bunny/Konstapel/issues/403)) ([f9b5e27](https://github.com/backend-bunny/Konstapel/commit/f9b5e2746e805c8b3a274aa30c2988205d19047c))
* **deps:** update go modules ([#210](https://github.com/backend-bunny/Konstapel/issues/210)) ([f2f5d97](https://github.com/backend-bunny/Konstapel/commit/f2f5d97b6e7c91d0e60cc63dbc027a683cdef4de))
* **images:** require image-signature payload in cosign verification ([#394](https://github.com/backend-bunny/Konstapel/issues/394)) ([c0da0d1](https://github.com/backend-bunny/Konstapel/commit/c0da0d13cdaf0f3bd607c9703b94876f65d2013e))
* **projection:** sanitized diagnostics and per-result attribution in namespace views ([#408](https://github.com/backend-bunny/Konstapel/issues/408)) ([3d145ed](https://github.com/backend-bunny/Konstapel/commit/3d145edb07f0d91fd7edcee7a2298bb0b69681c4))


### Build and Image

* **deps:** lock file maintenance ([#295](https://github.com/backend-bunny/Konstapel/issues/295)) ([c166077](https://github.com/backend-bunny/Konstapel/commit/c166077909ef51728f09129b1659c04a6dabf698))
* **deps:** lock go-licenses built with Go 1.27 ([#353](https://github.com/backend-bunny/Konstapel/issues/353)) ([c4684ea](https://github.com/backend-bunny/Konstapel/commit/c4684ead8286e95fba035ed1de4efb92581a7a48))

## [0.3.0](https://github.com/backend-bunny/Konstapel/compare/v0.2.0...v0.3.0) (2026-11-23)


### Features

* **attachments:** authenticated attachment transfers and konstapel evidence CLI (add-supporting-evidence-attachments 3.1-3.4) ([#289](https://github.com/backend-bunny/Konstapel/issues/289)) ([b36a544](https://github.com/backend-bunny/Konstapel/commit/b36a544856d65ccd5c6e81dd1a3b3911a6318058))
* **attachments:** chart values and protected-reader gate (7.1) ([#307](https://github.com/backend-bunny/Konstapel/issues/307)) ([bb21fb4](https://github.com/backend-bunny/Konstapel/commit/bb21fb42605acb7f6022b9d96b56985fcd82494b))
* **attachments:** EvidenceAttachment API, registrant admission, association validation and platform roles ([#282](https://github.com/backend-bunny/Konstapel/issues/282)) ([2b13d79](https://github.com/backend-bunny/Konstapel/commit/2b13d79028819959df601b35dff8f0f90ddebd1b))
* **attachments:** lifecycle states, no-event expiry, durable withdrawal and bounded cleanup (add-supporting-evidence-attachments 4.1-4.4) ([#291](https://github.com/backend-bunny/Konstapel/issues/291)) ([a69bf76](https://github.com/backend-bunny/Konstapel/commit/a69bf769629f50344b2cc0d0afb86d7b443cec03))
* **attachments:** RustFS local fixture, compat record and docs (add-supporting-evidence-attachments 6.1-6.3) ([#306](https://github.com/backend-bunny/Konstapel/issues/306)) ([5416663](https://github.com/backend-bunny/Konstapel/commit/5416663aea78463ae54e6a733a12e292004efa0c))
* **attachments:** source storage, commitment, frozen retention and retention-gated withdrawal (add-supporting-evidence-attachments 2.1-2.5) ([#284](https://github.com/backend-bunny/Konstapel/issues/284)) ([0bae86b](https://github.com/backend-bunny/Konstapel/commit/0bae86b7a022ba48815e18479011dbb5c5cf3701))
* **attachments:** supporting evidence in coverage and packages (5.1-5.5) ([#304](https://github.com/backend-bunny/Konstapel/issues/304)) ([deb326f](https://github.com/backend-bunny/Konstapel/commit/deb326fff1c26d1514cd23cca16f63180f771799))
* **availability:** serving readiness and per-replica admission (HA 3.1, 3.2) ([#312](https://github.com/backend-bunny/Konstapel/issues/312)) ([e9f9b2c](https://github.com/backend-bunny/Konstapel/commit/e9f9b2c29cda3efdb242014614de918f0ea1e9a7))
* **coverage:** attributed technical evidence (add-control-coverage-reporting 2.1, 2.2, 2.4) ([#298](https://github.com/backend-bunny/Konstapel/issues/298)) ([4efcc85](https://github.com/backend-bunny/Konstapel/commit/4efcc85fc342682c545ab149a5eab844df58c729))
* **coverage:** baseline and mapping inventory (add-control-coverage-reporting 1.1-1.4) ([#297](https://github.com/backend-bunny/Konstapel/issues/297)) ([6091cd1](https://github.com/backend-bunny/Konstapel/commit/6091cd1cfa3ecb719b2dcb4e39bd6a816d9110fd))
* **coverage:** bounded coverage status, current-summary requeues, inspection docs (add-control-coverage-reporting 3.3-3.5) ([#302](https://github.com/backend-bunny/Konstapel/issues/302)) ([b78b7b8](https://github.com/backend-bunny/Konstapel/commit/b78b7b8eede06c6e2a693af1280aeb34bf81448d))
* **coverage:** supporting-evidence context and scope projection (add-control-coverage-reporting 4.1-4.3) ([#303](https://github.com/backend-bunny/Konstapel/issues/303)) ([75c8894](https://github.com/backend-bunny/Konstapel/commit/75c8894161e2dc000987c76a8a8419b1a20cc066))
* **coverage:** versioned coverage reports in assessment packages (add-control-coverage-reporting 3.1, 3.2) ([#301](https://github.com/backend-bunny/Konstapel/issues/301)) ([8ba6965](https://github.com/backend-bunny/Konstapel/commit/8ba69654b35409b8481da216c8c42537e6e000f0))
* **evidence:** add EvidenceDestination signing policy and signing readiness ([#256](https://github.com/backend-bunny/Konstapel/issues/256)) ([a4b65f5](https://github.com/backend-bunny/Konstapel/commit/a4b65f553a9aab51ffa9ab79a01337d4f714334b))
* **evidence:** keep signature objects in the evidence lifecycle and make key dependencies visible ([#277](https://github.com/backend-bunny/Konstapel/issues/277)) ([66d3cf5](https://github.com/backend-bunny/Konstapel/commit/66d3cf592fcdfe3f4cdead9a01425d0320028412))
* **evidence:** retain evidence on signing failure and prove signing recovery (add-evidence-signing 3.4-3.6) ([#268](https://github.com/backend-bunny/Konstapel/issues/268)) ([f31032b](https://github.com/backend-bunny/Konstapel/commit/f31032b35b4a31aea3d251767e15569395a356cd))
* **evidence:** serve signatures beside archives after verifying the pair ([#276](https://github.com/backend-bunny/Konstapel/issues/276)) ([58fac90](https://github.com/backend-bunny/Konstapel/commit/58fac908bc022a51580eaa913fddac9f2dd16049))
* **evidence:** sign and gate publication commits (add-evidence-signing 3.1-3.3) ([#261](https://github.com/backend-bunny/Konstapel/issues/261)) ([e6ea47c](https://github.com/backend-bunny/Konstapel/commit/e6ea47cd842f4f3ebe56c4013bdc6eb6f1eac5e4))
* **exceptions:** persist independent revocation records (exceptions 3.6) ([#333](https://github.com/backend-bunny/Konstapel/issues/333)) ([a33d154](https://github.com/backend-bunny/Konstapel/commit/a33d1543919cc6358aefa47df1e47837fd974112))
* **exceptions:** revoke acceptances through spec.revoked (exceptions 2.5, 2.6) ([#332](https://github.com/backend-bunny/Konstapel/issues/332)) ([ff502eb](https://github.com/backend-bunny/Konstapel/commit/ff502eb557151897f379c4c8029e9c9bcddbfbc8))
* **observability:** authenticated TLS controller metrics and reader RBAC (add-prometheus-observability 3.1, 3.2) ([#283](https://github.com/backend-bunny/Konstapel/issues/283)) ([0dbe086](https://github.com/backend-bunny/Konstapel/commit/0dbe086b05887674680ff1c97e93d9c38912e672))
* **observability:** evaluate documented metric queries with a pinned promtool (add-prometheus-observability 1.6) ([#280](https://github.com/backend-bunny/Konstapel/issues/280)) ([2ef3c1f](https://github.com/backend-bunny/Konstapel/commit/2ef3c1f4a92ed275745675eb52e7543ace04e2f2))
* **observability:** optional ServiceMonitor and PrometheusRule chart values (add-prometheus-observability 4.1-4.4) ([#287](https://github.com/backend-bunny/Konstapel/issues/287)) ([62b48a2](https://github.com/backend-bunny/Konstapel/commit/62b48a23ac5824b2d0affb8e57f2e7e6ade59d8d))
* **observability:** record source-evaluation and schedule watermarks for assessment metrics ([#266](https://github.com/backend-bunny/Konstapel/issues/266)) ([9123884](https://github.com/backend-bunny/Konstapel/commit/9123884294e3026ee1bd21d1afdbefea39f86d14))
* **observability:** starter alert rules, runbooks and promtool suites (add-prometheus-observability 5.1-5.4) ([#288](https://github.com/backend-bunny/Konstapel/issues/288)) ([8b2010e](https://github.com/backend-bunny/Konstapel/commit/8b2010e2955df3a8d64312cd9b722309ec953ed2))
* **observability:** wire targeting, storage and bundle producers (add-prometheus-observability 2.1, 2.3, 2.4) ([#264](https://github.com/backend-bunny/Konstapel/issues/264)) ([ce61c20](https://github.com/backend-bunny/Konstapel/commit/ce61c200eab997f6b0fe47602065d43520dd1dd0))
* **preview:** epoch classification and evidence context (preview 5.2, 5.3) ([#334](https://github.com/backend-bunny/Konstapel/issues/334)) ([6b41975](https://github.com/backend-bunny/Konstapel/commit/6b4197553d1533985c8257a1c5bf16f907af7b08))
* **preview:** konstapel preview CLI, report v1, exit codes (preview 6.1-6.4) ([#331](https://github.com/backend-bunny/Konstapel/issues/331)) ([6c4b389](https://github.com/backend-bunny/Konstapel/commit/6c4b38905742d765aca1f2d90862f40b111bec35))
* **preview:** observe exception revocation (preview 2.5) ([#336](https://github.com/backend-bunny/Konstapel/issues/336)) ([a978499](https://github.com/backend-bunny/Konstapel/commit/a978499f239f1d3d546dce7c3f908c7c062232c6))
* **preview:** read-only cluster observation (preview 2.1, 2.3, 2.4) ([#328](https://github.com/backend-bunny/Konstapel/issues/328)) ([b05e6f7](https://github.com/backend-bunny/Konstapel/commit/b05e6f79fa2c0bb2f289d46aa6ca57d4a6789ddf))
* **preview:** rendered manifest inputs and candidate configuration (preview 1.1-1.4) ([#327](https://github.com/backend-bunny/Konstapel/issues/327)) ([99e63c9](https://github.com/backend-bunny/Konstapel/commit/99e63c93ccc93acc16ac22c033caddb760cc33a9))
* **preview:** shared resolution and semantic comparison (preview 3.1-3.5) ([#329](https://github.com/backend-bunny/Konstapel/issues/329)) ([9f22f71](https://github.com/backend-bunny/Konstapel/commit/9f22f71c1463e4f255f4597f5bf86e2b8aba6a0d))
* **preview:** verified bundle resolution under caller access (preview 4.1-4.4) ([#330](https://github.com/backend-bunny/Konstapel/issues/330)) ([7c20ea8](https://github.com/backend-bunny/Konstapel/commit/7c20ea80db5ac5353a5cae9bcfe4acf5e104fe41))


### Bug Fixes

* **assessment:** wait for first engine policy delivery before freezing a run's scope ([#278](https://github.com/backend-bunny/Konstapel/issues/278)) ([2a145c7](https://github.com/backend-bunny/Konstapel/commit/2a145c7229880deda3cd3f6bd0945cf955ddf3eb))
* **bundles:** resolve bundle content per name and digest ([#318](https://github.com/backend-bunny/Konstapel/issues/318)) ([3a6ae00](https://github.com/backend-bunny/Konstapel/commit/3a6ae00b5697a1f2ca1825ac93ad8c8e3699ac19))
* **deps:** update module go.opentelemetry.io/otel/sdk to v1.47.0 [security] ([#270](https://github.com/backend-bunny/Konstapel/issues/270)) ([155877b](https://github.com/backend-bunny/Konstapel/commit/155877bff88991dce2811937e67858076410c72b))
* **deps:** update module go.opentelemetry.io/otel/trace to v1.47.0 [security] ([#271](https://github.com/backend-bunny/Konstapel/issues/271)) ([829d915](https://github.com/backend-bunny/Konstapel/commit/829d915ec4af8ea958426b50eff87afc18c8d141))


### Build and Image

* **deps:** batch Renovate updates for 0.3.0 ([#337](https://github.com/backend-bunny/Konstapel/issues/337)) ([ab4d3df](https://github.com/backend-bunny/Konstapel/commit/ab4d3df772b8472912e9c5f4e85992fff6249617))
* **deps:** refresh image runtime lock ([#341](https://github.com/backend-bunny/Konstapel/issues/341)) ([9e479df](https://github.com/backend-bunny/Konstapel/commit/9e479df1a1787ae31a439b3022f651326a48508d))
* **deps:** update dependency jetify-com/devbox to v0.21.0 ([#263](https://github.com/backend-bunny/Konstapel/issues/263)) ([a117ed6](https://github.com/backend-bunny/Konstapel/commit/a117ed6ff4a928d1de971d21da8864c7d46f087c))
* **deps:** update dependency jetify-com/devbox to v0.22.0 ([#305](https://github.com/backend-bunny/Konstapel/issues/305)) ([c2ba5f0](https://github.com/backend-bunny/Konstapel/commit/c2ba5f0da9a7547781507e6f415163d7db7ae772))
* **deps:** update Go modules held below crypto/mldsa ([#265](https://github.com/backend-bunny/Konstapel/issues/265)) ([be5c6d0](https://github.com/backend-bunny/Konstapel/commit/be5c6d0e51271e0cfcb9172efef128e663dc8d6c))
* **test:** raise the Go unit test package timeout to 30m ([#274](https://github.com/backend-bunny/Konstapel/issues/274)) ([efd4ff4](https://github.com/backend-bunny/Konstapel/commit/efd4ff45da268aad847a41ef7415546e743481fe))

## [0.2.0](https://github.com/backend-bunny/Konstapel/compare/v0.1.0...v0.2.0) (2026-11-13)


### Features

* **assessment:** export OCI-bundle runs from their frozen bundle ([#235](https://github.com/backend-bunny/Konstapel/issues/235)) ([566c831](https://github.com/backend-bunny/Konstapel/commit/566c8312cbec26cd0bd052490def41b620316e54))
* **assessment:** freeze and export each run's applied bundle content ([#244](https://github.com/backend-bunny/Konstapel/issues/244)) ([78e3e32](https://github.com/backend-bunny/Konstapel/commit/78e3e3246573ee6f13f849f0800e87b8353a26dc))
* **bundle:** acceptance, leases, eviction and retained proofs (tasks 4.2-4.4) ([#222](https://github.com/backend-bunny/Konstapel/issues/222)) ([75e339a](https://github.com/backend-bunny/Konstapel/commit/75e339a66cbf16708af5e935a6876122d89c484e))
* **bundle:** add bounded digest/referrer registry retrieval (2.2) ([#208](https://github.com/backend-bunny/Konstapel/issues/208)) ([7a5aac9](https://github.com/backend-bunny/Konstapel/commit/7a5aac93e8c0a947e05f9723b45ff8d5b5d5157b))
* **bundle:** add policy bundle descriptor and OCI layout contract ([#200](https://github.com/backend-bunny/Konstapel/issues/200)) ([94b9cff](https://github.com/backend-bunny/Konstapel/commit/94b9cfff4c2d61a44925b7bd80ba0e84a0ebd150))
* **bundle:** add the bundles:package workflow and authoring docs ([#203](https://github.com/backend-bunny/Konstapel/issues/203)) ([02c3c1b](https://github.com/backend-bunny/Konstapel/commit/02c3c1b768c82c504a79f612971f619c58dfa4df))
* **bundle:** assemble the Linux hardening bundle by reference to owned content ([#247](https://github.com/backend-bunny/Konstapel/issues/247)) ([c6f1233](https://github.com/backend-bunny/Konstapel/commit/c6f1233c04f4ed1a25b588382592c8c71474e2fe))
* **bundle:** build and unpack bundle archives deterministically ([#201](https://github.com/backend-bunny/Konstapel/issues/201)) ([1ead7d4](https://github.com/backend-bunny/Konstapel/commit/1ead7d4c2fb5ee0f72ea115ee47819d2e130d92d))
* **bundle:** builder-record provenance, exact keyless rules, Linux-only scope ([#237](https://github.com/backend-bunny/Konstapel/issues/237)) ([0873755](https://github.com/backend-bunny/Konstapel/commit/087375554c995a06ec88f2405c362f1cf504e90a))
* **bundle:** central source watcher and detailed content conditions (tasks 5.1/5.3 core) ([#227](https://github.com/backend-bunny/Konstapel/issues/227)) ([a1525f4](https://github.com/backend-bunny/Konstapel/commit/a1525f4db9a5aaf8bc52c98a99660c3b7ecb15f4))
* **bundle:** define the central bundle source configuration ([#207](https://github.com/backend-bunny/Konstapel/issues/207)) ([3cfaf8c](https://github.com/backend-bunny/Konstapel/commit/3cfaf8ca60711b977ec863f5ee629fa6d3427fc3))
* **bundle:** define the first policy bundle, konstapel-privileged-containers ([#202](https://github.com/backend-bunny/Konstapel/issues/202)) ([80dd9b4](https://github.com/backend-bunny/Konstapel/commit/80dd9b4df8b9d0bad570af5660c04e26b6f80d0b))
* **bundle:** freeze tested bundles and publish them write-once (task 6.2) ([#218](https://github.com/backend-bunny/Konstapel/issues/218)) ([834c259](https://github.com/backend-bunny/Konstapel/commit/834c259212c1f11d41faf42b81f361a7f7107e53))
* **bundle:** Helm chart wiring and live acceptance for OCI bundles (stage 2b-ii) ([#230](https://github.com/backend-bunny/Konstapel/issues/230)) ([b6170bf](https://github.com/backend-bunny/Konstapel/commit/b6170bf11dc34216d70557ba08e0a233ba1f09c0))
* **bundle:** isolated extraction and atomic digest cache (tasks 4.1, 4.2) ([#221](https://github.com/backend-bunny/Konstapel/issues/221)) ([119879b](https://github.com/backend-bunny/Konstapel/commit/119879bbd99ba6eee10887e5d93128f9c6d73776))
* **bundle:** mirror published bundles with their proofs (task 6.5) ([#228](https://github.com/backend-bunny/Konstapel/issues/228)) ([907c97d](https://github.com/backend-bunny/Konstapel/commit/907c97dad9ff91aee559f5b83a5e48da1b62acda))
* **bundle:** per-source token realm allowlist for registry credentials ([#236](https://github.com/backend-bunny/Konstapel/issues/236)) ([1670415](https://github.com/backend-bunny/Konstapel/commit/167041552af8db38da8ac98d9812b017b0e5a04a))
* **bundle:** publish the resolved-content handle and receipt contract ([#205](https://github.com/backend-bunny/Konstapel/issues/205)) ([7bbe9ab](https://github.com/backend-bunny/Konstapel/commit/7bbe9abab35663c3331370763706ee7e18527253))
* **bundle:** referrers tag-schema fallback and real-registry fixture (task 2.4) ([#209](https://github.com/backend-bunny/Konstapel/issues/209)) ([5adf4a1](https://github.com/backend-bunny/Konstapel/commit/5adf4a18dca928f081eab8bbccb46fc0b05c079a))
* **bundle:** reject Docker Hub aliases at configuration load ([#239](https://github.com/backend-bunny/Konstapel/issues/239)) ([ad9f088](https://github.com/backend-bunny/Konstapel/commit/ad9f088d086acba2eed1e040b0477817eef9f440))
* **bundle:** render release notes and announce verified bundle releases ([#220](https://github.com/backend-bunny/Konstapel/issues/220)) ([8e88506](https://github.com/backend-bunny/Konstapel/commit/8e88506a0808890ce6f7e4c849fc5321d648c3de))
* **bundle:** Secret-backed registry credentials and custom CAs (task 2.3) ([#211](https://github.com/backend-bunny/Konstapel/issues/211)) ([264d60d](https://github.com/backend-bunny/Konstapel/commit/264d60d80094e8c8703fedcea0754d2b380b21f9))
* **bundle:** sign, attest and verify released bundle digests (task 6.3) ([#219](https://github.com/backend-bunny/Konstapel/issues/219)) ([e3136c9](https://github.com/backend-bunny/Konstapel/commit/e3136c95e9882c988b18a1a5e8efd39c52ab2520))
* **bundle:** validate and tag independent bundle releases ([#206](https://github.com/backend-bunny/Konstapel/issues/206)) ([24c2cdf](https://github.com/backend-bunny/Konstapel/commit/24c2cdfcb5264af0bc88d9e4a149564f44010620))
* **bundle:** validate bundle content, references and parameters ([#204](https://github.com/backend-bunny/Konstapel/issues/204)) ([5e94982](https://github.com/backend-bunny/Konstapel/commit/5e9498230d1398b7bc532106da1936d0676b6888))
* **bundle:** verified OCI content source for targeting (task 5.2 core) ([#226](https://github.com/backend-bunny/Konstapel/issues/226)) ([28ba4ba](https://github.com/backend-bunny/Konstapel/commit/28ba4baef39456c0d0d908076df551e16f5e31da))
* **bundle:** verify bundle provenance and persist recheckable receipts (tasks 3.3, 3.4) ([#215](https://github.com/backend-bunny/Konstapel/issues/215)) ([2e10c16](https://github.com/backend-bunny/Konstapel/commit/2e10c168b45bbb539e06f2998ed2272690d565a3))
* **bundle:** verify publisher signatures offline (tasks 3.1, 3.2) ([#214](https://github.com/backend-bunny/Konstapel/issues/214)) ([591d6fe](https://github.com/backend-bunny/Konstapel/commit/591d6fea5e6517bffc906540cec1e94c3def738a))
* **bundle:** wire verified OCI bundle content into the controller (default off) ([#229](https://github.com/backend-bunny/Konstapel/issues/229)) ([24f0bd7](https://github.com/backend-bunny/Konstapel/commit/24f0bd77ee3a36ad8931ca36c072d44627df9eb2))
* **evidence:** add Secret-key evidence signer and offline verification contract ([#255](https://github.com/backend-bunny/Konstapel/issues/255)) ([046cbb8](https://github.com/backend-bunny/Konstapel/commit/046cbb8ce839ae86cc0c3d958f7cc50cc8682a32))
* **observability:** metric catalog contract and leader-scoped projections (add-prometheus-observability 1.1-1.5) ([#252](https://github.com/backend-bunny/Konstapel/issues/252)) ([bf1f048](https://github.com/backend-bunny/Konstapel/commit/bf1f0486e4d57aec08be18cb6efc4d16435988ae))
* **observability:** reconcile check states with the assessment owner (warn/stale replacements) ([#259](https://github.com/backend-bunny/Konstapel/issues/259)) ([aae2c66](https://github.com/backend-bunny/Konstapel/commit/aae2c66c26600d6957e633e4a2cd481d57eb3487))


### Bug Fixes

* **bundle:** require Konstapel 0.2.0 for the hardening bundle and accept it live over OCI ([#262](https://github.com/backend-bunny/Konstapel/issues/262)) ([c8a4ec8](https://github.com/backend-bunny/Konstapel/commit/c8a4ec89df236ed3c50f1abcc7fc794f8fd3d5bc))
* **deps:** update go modules ([#197](https://github.com/backend-bunny/Konstapel/issues/197)) ([07570f8](https://github.com/backend-bunny/Konstapel/commit/07570f81d99a83a02ecf8540934e194534979ec9))
* **deps:** update module github.com/go-jose/go-jose/v4 to v4.1.6 [security] ([#216](https://github.com/backend-bunny/Konstapel/issues/216)) ([58a666e](https://github.com/backend-bunny/Konstapel/commit/58a666e31f641705d331d53b93b86deafb9b020d))
* **rbac:** audit controller Secret/ConfigMap access, drop unused ConfigMap list ([#234](https://github.com/backend-bunny/Konstapel/issues/234)) ([458886d](https://github.com/backend-bunny/Konstapel/commit/458886de273ab2ccf84d94b0086c987f5739fde3))
* **rbac:** limit controller Lease access to the leader-election Lease ([#238](https://github.com/backend-bunny/Konstapel/issues/238)) ([ed4ed58](https://github.com/backend-bunny/Konstapel/commit/ed4ed580bdfa3e88d6f55d00176cfa84f5cec757))


### Build and Image

* **deps:** update dependency jetify-com/devbox to v0.20.0 ([#198](https://github.com/backend-bunny/Konstapel/issues/198)) ([4c737fd](https://github.com/backend-bunny/Konstapel/commit/4c737fd417a61caf43fca3ecf75a601d78f68d41))
* **deps:** update development tools ([#233](https://github.com/backend-bunny/Konstapel/issues/233)) ([8b9fb4d](https://github.com/backend-bunny/Konstapel/commit/8b9fb4defd493bc177d32f1b064a64946c334b85))

## 0.1.0 (2026-11-09)


### ⚠ BREAKING CHANGES

* **destinations:** --evidence-destination is removed. Create an EvidenceDestination (with spec.legacy for existing evidence) and select it as the central default before upgrading.

### Features

* add continuous-assessment request/run and publication contract ([#56](https://github.com/backend-bunny/Konstapel/issues/56)) ([1c990bb](https://github.com/backend-bunny/Konstapel/commit/1c990bb7deef071ab6a7bd7db507779aa9cabee7))
* **api:** add binding assessment settings and enforcement epoch ([#74](https://github.com/backend-bunny/Konstapel/issues/74)) ([f34beb9](https://github.com/backend-bunny/Konstapel/commit/f34beb929c9ecdc5b88601d9ef534ec93415b46e))
* **api:** add compliance targeting v1alpha1 API contract ([#50](https://github.com/backend-bunny/Konstapel/issues/50)) ([9b4ae32](https://github.com/backend-bunny/Konstapel/commit/9b4ae322fe34d28684b774e3e1ae163feab13702))
* **api:** add namespaced ComplianceException CRD ([#100](https://github.com/backend-bunny/Konstapel/issues/100)) ([cc7d93f](https://github.com/backend-bunny/Konstapel/commit/cc7d93fb8791b5ff4bcdd2083df1c9cd4d0b4715))
* **api:** add the platform-managed EvidenceDestination resource ([#125](https://github.com/backend-bunny/Konstapel/issues/125)) ([662b9a7](https://github.com/backend-bunny/Konstapel/commit/662b9a781194105db353bd49ecf9e0c821f13ffd))
* **capability:** discover engine capabilities and report precise reasons ([#161](https://github.com/backend-bunny/Konstapel/issues/161)) ([7f1bc10](https://github.com/backend-bunny/Konstapel/commit/7f1bc107fd1d5965beb1b6f8d9618faa1d21513e))
* **charts:** bind availability acceptance to the frozen release artifacts ([#189](https://github.com/backend-bunny/Konstapel/issues/189)) ([b54503c](https://github.com/backend-bunny/Konstapel/commit/b54503c8872ea842bebb514ae3f78f04fad5bcfd))
* **charts:** package, accept and publish frozen chart archives ([#179](https://github.com/backend-bunny/Konstapel/issues/179)) ([cc9f396](https://github.com/backend-bunny/Konstapel/commit/cc9f396f149635923de6e68f8f193edbbc707368))
* **charts:** serve evidence downloads with verified TLS ([#168](https://github.com/backend-bunny/Konstapel/issues/168)) ([c47edf8](https://github.com/backend-bunny/Konstapel/commit/c47edf8a65c8c1cc7b8d46a9fa25b93165a4d3d7))
* **charts:** sign, attest, verify and release the frozen charts ([#181](https://github.com/backend-bunny/Konstapel/issues/181)) ([eb99812](https://github.com/backend-bunny/Konstapel/commit/eb99812114d61bd889c53b2da135f8127a412f44))
* **collector:** add freshness and continuity rules ([#71](https://github.com/backend-bunny/Konstapel/issues/71)) ([7eab86c](https://github.com/backend-bunny/Konstapel/commit/7eab86c27cbdb1445703404813b1dd0021d22f6b))
* **collector:** add v2 capture inventory and scope tracking ([#69](https://github.com/backend-bunny/Konstapel/issues/69)) ([3340b58](https://github.com/backend-bunny/Konstapel/commit/3340b58db481e3ac4691ef48391ae28af5e21801))
* **collector:** export v2 captures as OSCAL or diagnostic packages ([#79](https://github.com/backend-bunny/Konstapel/issues/79)) ([ff39586](https://github.com/backend-bunny/Konstapel/commit/ff39586ce5b8562fbc7a6dae1dd2b14a255e01eb))
* **collector:** project evidence to one namespace before export ([#81](https://github.com/backend-bunny/Konstapel/issues/81)) ([7d08e50](https://github.com/backend-bunny/Konstapel/commit/7d08e5082251a014291d83dc97e85f971779333c))
* **collector:** verify engine policies against pinned content ([#83](https://github.com/backend-bunny/Konstapel/issues/83)) ([e93e465](https://github.com/backend-bunny/Konstapel/commit/e93e465c6fc59f7613fd42449953faa4b22601f0))
* **content:** bounded NIST Moderate mappings for the hardening checks ([#118](https://github.com/backend-bunny/Konstapel/issues/118)) ([03abe87](https://github.com/backend-bunny/Konstapel/commit/03abe87fe53b6f55265b5c496432451a89460bba))
* **content:** Konstapel Linux variants of the hardening checks ([#115](https://github.com/backend-bunny/Konstapel/issues/115)) ([3c26860](https://github.com/backend-bunny/Konstapel/commit/3c26860a1435df452ac0984f246ceb7c71178156))
* **content:** vendor the four Linux hardening policy sources ([#112](https://github.com/backend-bunny/Konstapel/issues/112)) ([d5a503a](https://github.com/backend-bunny/Konstapel/commit/d5a503a5eb4047dca1e68ee730ab9c4f4bc0a290))
* **controller:** add the targeting manager ([#66](https://github.com/backend-bunny/Konstapel/issues/66)) ([f192b6e](https://github.com/backend-bunny/Konstapel/commit/f192b6e560a1bedafe93845aba3b5caa840fb9e1))
* **controller:** bound shutdown and leave endpoints while draining ([#165](https://github.com/backend-bunny/Konstapel/issues/165)) ([6e491d5](https://github.com/backend-bunny/Konstapel/commit/6e491d5a7817e41304cd56d01a111de7566b9c14))
* **controller:** gate scheduling on backend readiness and keep closure retention ([#89](https://github.com/backend-bunny/Konstapel/issues/89)) ([56e1c85](https://github.com/backend-bunny/Konstapel/commit/56e1c850706d1b4852c32d09feb32c6b8c19b0fe))
* **controller:** reconcile current assessment status ([#78](https://github.com/backend-bunny/Konstapel/issues/78)) ([3551869](https://github.com/backend-bunny/Konstapel/commit/3551869d1b6319e06993050195a0a30cc546271f))
* **controller:** recover runs without rewriting their snapshot ([#84](https://github.com/backend-bunny/Konstapel/issues/84)) ([7d4bfe6](https://github.com/backend-bunny/Konstapel/commit/7d4bfe6877d0a50550c95b5d54883a16741e3db8))
* **controller:** run team assessment requests as namespace runs ([#82](https://github.com/backend-bunny/Konstapel/issues/82)) ([de3e47c](https://github.com/backend-bunny/Konstapel/commit/de3e47c0777b25217d0c9a3a5034636f22d6afff))
* **controller:** schedule and execute assessment runs ([#80](https://github.com/backend-bunny/Konstapel/issues/80)) ([fd1143e](https://github.com/backend-bunny/Konstapel/commit/fd1143e6b78a85fbbff984b606780205772f9058))
* **controller:** serve the hardening variants in the vendored bundle ([#119](https://github.com/backend-bunny/Konstapel/issues/119)) ([926628a](https://github.com/backend-bunny/Konstapel/commit/926628a57037920d84cd0f58864946b4d1a3e61f))
* **controller:** share one validated election Lease across replicas ([#164](https://github.com/backend-bunny/Konstapel/issues/164)) ([c463d09](https://github.com/backend-bunny/Konstapel/commit/c463d097583119e264b06162f04d307260412f05))
* **controller:** wire the S3 evidence destination into the controller ([#90](https://github.com/backend-bunny/Konstapel/issues/90)) ([d4ea2f7](https://github.com/backend-bunny/Konstapel/commit/d4ea2f74f4b7f68b5c1d0896f2a0e7ee2de9d899))
* **destinations:** fence all storage work after an orphan handoff ([#138](https://github.com/backend-bunny/Konstapel/issues/138)) ([c060cd2](https://github.com/backend-bunny/Konstapel/commit/c060cd2e26efaf356ab36e60cdab5b01db2ec0f6))
* **destinations:** mark handed-off runs Orphaned and finalize ([#140](https://github.com/backend-bunny/Konstapel/issues/140)) ([9e2511e](https://github.com/backend-bunny/Konstapel/commit/9e2511e4a87a6209ae6a745d34909e9040dfcfc6))
* **destinations:** migrate legacy runs to verified destinations ([#155](https://github.com/backend-bunny/Konstapel/issues/155)) ([1fa02f4](https://github.com/backend-bunny/Konstapel/commit/1fa02f42df9c25ee9807915968b1091a6e63aa28))
* **destinations:** never adopt orphaned ownership ([#141](https://github.com/backend-bunny/Konstapel/issues/141)) ([cae88bd](https://github.com/backend-bunny/Konstapel/commit/cae88bd32611dbf2509ff26abc9d0e07fe451db6))
* **destinations:** persist a chunked orphan inventory before release ([#139](https://github.com/backend-bunny/Konstapel/issues/139)) ([9288a85](https://github.com/backend-bunny/Konstapel/commit/9288a85e8561a575e5f080473d59245d88e847f4))
* **destinations:** pin runs to destinations and route storage through pins ([#134](https://github.com/backend-bunny/Konstapel/issues/134)) ([f3a7b65](https://github.com/backend-bunny/Konstapel/commit/f3a7b65119cbfec0fb496cbda38a0b17b53705d7))
* **destinations:** record an authenticated, irreversible orphan intent ([#137](https://github.com/backend-bunny/Konstapel/issues/137)) ([6cfcb7b](https://github.com/backend-bunny/Konstapel/commit/6cfcb7b0ceef272f4445469838681383ae6af95f))
* **destinations:** retire destinations until their obligations end ([#135](https://github.com/backend-bunny/Konstapel/issues/135)) ([8e50d18](https://github.com/backend-bunny/Konstapel/commit/8e50d187021d137077e4389e6874425610168780))
* **destinations:** select evidence destinations by name and UID ([#131](https://github.com/backend-bunny/Konstapel/issues/131)) ([0f920f6](https://github.com/backend-bunny/Konstapel/commit/0f920f671aa24c8ad47f2926841ea92c52950384))
* **download:** reload rotated serving certificates without a restart ([#170](https://github.com/backend-bunny/Konstapel/issues/170)) ([30e4f8a](https://github.com/backend-bunny/Konstapel/commit/30e4f8a6a60d94b1ed850d3dce36d69a559fb66f))
* **download:** serve published evidence under current Kubernetes RBAC ([#99](https://github.com/backend-bunny/Konstapel/issues/99)) ([530f3eb](https://github.com/backend-bunny/Konstapel/commit/530f3eb7edbab70906bbee270ed9be891696b106))
* **exceptions:** enforce eligibility and lifetime at acceptance ([#104](https://github.com/backend-bunny/Konstapel/issues/104)) ([2bf9512](https://github.com/backend-bunny/Konstapel/commit/2bf951246d0cc1f84048856af84ddff04229372c))
* **exceptions:** persist immutable acceptance snapshots ([#107](https://github.com/backend-bunny/Konstapel/issues/107)) ([a25ec62](https://github.com/backend-bunny/Konstapel/commit/a25ec6297ebc5fd1d3c834ecc41a6b85cf655e6b))
* **exceptions:** record authenticated acceptances at admission ([#102](https://github.com/backend-bunny/Konstapel/issues/102)) ([45deeaf](https://github.com/backend-bunny/Konstapel/commit/45deeaf207941df00f1ae6b7f60cbf4e322485fb))
* **export:** plan and map exactly the assessed checks across definitions ([#122](https://github.com/backend-bunny/Konstapel/issues/122)) ([0bd7209](https://github.com/backend-bunny/Konstapel/commit/0bd720914fbf864040e70bc4f04fdf68cc586aec))
* **hardening:** assess background evidence and keep Windows out of scope ([#180](https://github.com/backend-bunny/Konstapel/issues/180)) ([fc268a8](https://github.com/backend-bunny/Konstapel/commit/fc268a8b9b92e0b1540f4f8fd8b269196c6e3187))
* **rbac:** namespace exception role and controller-only exception status ([#106](https://github.com/backend-bunny/Konstapel/issues/106)) ([1b1f465](https://github.com/backend-bunny/Konstapel/commit/1b1f4653757ca930c1f1a6a68889ea82ff1eb616))
* **retention:** report early loss and corruption of retained packages ([#105](https://github.com/backend-bunny/Konstapel/issues/105)) ([a7cfa02](https://github.com/backend-bunny/Konstapel/commit/a7cfa022805f312d3dd946c0f647f63c781d615b))
* **retention:** retain published evidence until expiry, then delete it ([#103](https://github.com/backend-bunny/Konstapel/issues/103)) ([8955900](https://github.com/backend-bunny/Konstapel/commit/89559000bf61962225f7b0ac2acbec53e52901f4))
* **s3store:** add evidence destination config and compatibility probe ([#86](https://github.com/backend-bunny/Konstapel/issues/86)) ([0e9ffc3](https://github.com/backend-bunny/Konstapel/commit/0e9ffc31ef242dd1bea78fecba46972fb6146b6d))
* **s3store:** clean up uncommitted attempts of terminal runs ([#96](https://github.com/backend-bunny/Konstapel/issues/96)) ([8606ec7](https://github.com/backend-bunny/Konstapel/commit/8606ec733346165bc5c05f47559d1b716a242fc7))
* **s3store:** publish packages with verified create-if-absent commits ([#87](https://github.com/backend-bunny/Konstapel/issues/87)) ([ed79241](https://github.com/backend-bunny/Konstapel/commit/ed79241f883a6f4e5ac12b14ccc3c5ec7277d243))
* **schedule:** add snapshot scheduler and binding assessment status ([#76](https://github.com/backend-bunny/Konstapel/issues/76)) ([323fd9b](https://github.com/backend-bunny/Konstapel/commit/323fd9b0465888b6cc277b8105176c92284e5f95))
* **targeting:** publish expected-evidence subjects ([#68](https://github.com/backend-bunny/Konstapel/issues/68)) ([04ac416](https://github.com/backend-bunny/Konstapel/commit/04ac4166a29cae038097effa87aceb5b8bda5ff1))
* **targeting:** render and deliver versioned engine policies ([#60](https://github.com/backend-bunny/Konstapel/issues/60)) ([fb8402f](https://github.com/backend-bunny/Konstapel/commit/fb8402fb6a6eda330e338c9e8bb48bd2d25e8582))
* **targeting:** resolve bindings into contributions and eligibility ([#53](https://github.com/backend-bunny/Konstapel/issues/53)) ([fb11da0](https://github.com/backend-bunny/Konstapel/commit/fb11da0a8b46f2b30e6d572a11eefc7579770982))


### Bug Fixes

* **acceptance:** wait for the loaded controller image in kind ([#186](https://github.com/backend-bunny/Konstapel/issues/186)) ([9f13099](https://github.com/backend-bunny/Konstapel/commit/9f130990a348ea23b1e4fefc02baf3bba6c2415a))
* **assessments:** no orphaned first scheduled run; prove deployed durable recovery ([#190](https://github.com/backend-bunny/Konstapel/issues/190)) ([fcbc2a1](https://github.com/backend-bunny/Konstapel/commit/fcbc2a1d8d1091051b2d23f4793b390f9f280c71))
* **capability:** recover live from engine and permission changes ([#163](https://github.com/backend-bunny/Konstapel/issues/163)) ([ad21e8c](https://github.com/backend-bunny/Konstapel/commit/ad21e8c7a6e6a2b08b375e3615786800d74350a6))
* **collector:** attribute Kyverno's policy-level passes to every validation ([#133](https://github.com/backend-bunny/Konstapel/issues/133)) ([f370212](https://github.com/backend-bunny/Konstapel/commit/f37021203b9a96cef43fde586fba26e46c37e709))
* **controller:** re-check ownership conflicts; verify failure modes live ([#92](https://github.com/backend-bunny/Konstapel/issues/92)) ([e5a04a5](https://github.com/backend-bunny/Konstapel/commit/e5a04a50e9a815212600e6ce99904044fe62f121))
* **deps:** migrate JSON Schema validation to v6 ([#52](https://github.com/backend-bunny/Konstapel/issues/52)) ([6cab48c](https://github.com/backend-bunny/Konstapel/commit/6cab48c932e6c02e701d1a45edda5b8baae7c332))
* **deps:** update go modules ([#129](https://github.com/backend-bunny/Konstapel/issues/129)) ([ca4d5b4](https://github.com/backend-bunny/Konstapel/commit/ca4d5b42fd98157416989c7aa4064ee13df732e7))
* **deps:** update go modules ([#43](https://github.com/backend-bunny/Konstapel/issues/43)) ([bd3a162](https://github.com/backend-bunny/Konstapel/commit/bd3a16220145c98488d22ff43ad4a831a3241a04))
* **deps:** update go modules ([#64](https://github.com/backend-bunny/Konstapel/issues/64)) ([15fb990](https://github.com/backend-bunny/Konstapel/commit/15fb9904f4642894ec42b0af748ac39b77225b01))
* **deps:** update k8s.io/utils digest to ca04ba5 ([#154](https://github.com/backend-bunny/Konstapel/issues/154)) ([2d80af1](https://github.com/backend-bunny/Konstapel/commit/2d80af1120a3733e7b7bed4b2b2bea1b995051f4))
* **deps:** update module github.com/go-git/go-git/v5 to v5.19.2 [security] ([#37](https://github.com/backend-bunny/Konstapel/issues/37)) ([5ff2f41](https://github.com/backend-bunny/Konstapel/commit/5ff2f417a2506f35a87cc71d533e24dfe61bc4d5))
* **deps:** update module github.com/google/cel-go to v0.29.0 [security] ([#55](https://github.com/backend-bunny/Konstapel/issues/55)) ([ebe03ee](https://github.com/backend-bunny/Konstapel/commit/ebe03eed7a51fb36c0c3178e5b065f91cebfa13d))
* **deps:** update module go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc to v1.45.0 [security] ([#58](https://github.com/backend-bunny/Konstapel/issues/58)) ([ca311e9](https://github.com/backend-bunny/Konstapel/commit/ca311e99595e451b9f330c3e29c69c643d632023))
* **deps:** update module google.golang.org/grpc to v1.83.1 [security] ([#40](https://github.com/backend-bunny/Konstapel/issues/40)) ([42adc88](https://github.com/backend-bunny/Konstapel/commit/42adc88c3a8fe85df81306658e0f39027cae35dc))
* **deps:** update module google.golang.org/grpc to v1.83.2 [security] ([#45](https://github.com/backend-bunny/Konstapel/issues/45)) ([3a5d552](https://github.com/backend-bunny/Konstapel/commit/3a5d55239a03dee882477d9c1d2cc709cec144ac))
* **destinations:** keep a team run's namespace scope when pinning ([#149](https://github.com/backend-bunny/Konstapel/issues/149)) ([ea22830](https://github.com/backend-bunny/Konstapel/commit/ea2283069532bf845399c1801150c4810031635f))
* **export:** link every contributing mapping; target mapped statements ([#127](https://github.com/backend-bunny/Konstapel/issues/127)) ([1fa32f0](https://github.com/backend-bunny/Konstapel/commit/1fa32f0690c0cd751140dc114027f85c3a21a4c8))
* **retention:** honor the backoff between failed expiry deletions ([#152](https://github.com/backend-bunny/Konstapel/issues/152)) ([c3903b8](https://github.com/backend-bunny/Konstapel/commit/c3903b86b75bcff861df24c2022d0351d30848a8))
* **s3store:** reuse staged uploads and commits on retry ([#95](https://github.com/backend-bunny/Konstapel/issues/95)) ([5ca49d2](https://github.com/backend-bunny/Konstapel/commit/5ca49d24c58a7830894216ee40b7bd1cda0eedf1))
* **scheduler:** never create runs from a stale binding; verify faults live ([#117](https://github.com/backend-bunny/Konstapel/issues/117)) ([4b1c72a](https://github.com/backend-bunny/Konstapel/commit/4b1c72a0c032424176ff46749bbdefcb8eaf9244))
* **targeting:** keep reporting-only edits off engine policies ([#75](https://github.com/backend-bunny/Konstapel/issues/75)) ([7ed4890](https://github.com/backend-bunny/Konstapel/commit/7ed489002934178d8bacb2eebac6d9d52d175e48))
* **targeting:** refuse stale-snapshot deliveries and precondition deletes ([#175](https://github.com/backend-bunny/Konstapel/issues/175)) ([d529788](https://github.com/backend-bunny/Konstapel/commit/d52978861daed98b7e8366b8f63cc67ae00e7f93))


### Build and Image

* automate releases and image summaries ([#35](https://github.com/backend-bunny/Konstapel/issues/35)) ([4dc7afb](https://github.com/backend-bunny/Konstapel/commit/4dc7afb67b902302b52195c3e8ab4e67ab3dfb78))
* **charts:** freeze and verify the chart publication manifest ([#160](https://github.com/backend-bunny/Konstapel/issues/160)) ([75cba00](https://github.com/backend-bunny/Konstapel/commit/75cba00c701431d56273f9f70bafd3dd9ddc38c7))
* **charts:** package the generated CRDs and prove their lifecycle ([#158](https://github.com/backend-bunny/Konstapel/issues/158)) ([9418ff6](https://github.com/backend-bunny/Konstapel/commit/9418ff6ce36ec561eba9fe84f3cd9fd9d16cc0de))
* **charts:** render the controller with its RBAC and availability defaults ([#166](https://github.com/backend-bunny/Konstapel/issues/166)) ([427730b](https://github.com/backend-bunny/Konstapel/commit/427730b0a29d6443b082224f663cc34286d0217b))
* **charts:** scaffold the CRD and runtime Helm charts ([#156](https://github.com/backend-bunny/Konstapel/issues/156)) ([141bff9](https://github.com/backend-bunny/Konstapel/commit/141bff94f61abd3506e2d8747edfcf4f04460a67))
* **deps:** lock file maintenance ([#194](https://github.com/backend-bunny/Konstapel/issues/194)) ([3ef9ba5](https://github.com/backend-bunny/Konstapel/commit/3ef9ba564f2fbd7129cacf7ef26281b95c30b901))
* **deps:** update dependency jetify-com/devbox to v0.19.0 ([#44](https://github.com/backend-bunny/Konstapel/issues/44)) ([b452ff3](https://github.com/backend-bunny/Konstapel/commit/b452ff36180217e6840c679918a20578cb5d8b74))
* **deps:** update dependency kubernetes-controller-tools to v0.23.0 ([#63](https://github.com/backend-bunny/Konstapel/issues/63)) ([a3a41de](https://github.com/backend-bunny/Konstapel/commit/a3a41de55f750a23970076c4e5da610dab84a9e4))
* **deps:** update dependency renovate to v44.216.0 ([#153](https://github.com/backend-bunny/Konstapel/issues/153)) ([0f91dfc](https://github.com/backend-bunny/Konstapel/commit/0f91dfc0dcefc9a3e83667048e46c7e38bb1fbfb))
* **deps:** update go module directive to v1.27.3 ([#47](https://github.com/backend-bunny/Konstapel/issues/47)) ([894a495](https://github.com/backend-bunny/Konstapel/commit/894a495c44b8365d0690e61d1f0de3bb6889f0c0))
* **deps:** update kubernetes test environment ([#65](https://github.com/backend-bunny/Konstapel/issues/65)) ([b2bde0e](https://github.com/backend-bunny/Konstapel/commit/b2bde0e8b6f5248b909ab911ff9f04e97bcc9763))
* standardize tooling and signed image builds ([#33](https://github.com/backend-bunny/Konstapel/issues/33)) ([1133557](https://github.com/backend-bunny/Konstapel/commit/1133557ed3148891011ab810773480d0c242fa9c))
