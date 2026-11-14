{{/*
Runtime templates use the controller's merged entry point and the inputs in
docs/charts.md. The generated-*.yaml manifests are copied unchanged from
config/rbac and config/admission by scripts/charts/runtime.sh.
*/}}
{{- define "konstapel.labels" -}}
app.kubernetes.io/name: konstapel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: konstapel
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Stable selector across revisions: no version or template hash. */}}
{{- define "konstapel.controllerSelector" -}}
app.kubernetes.io/name: konstapel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{/* Fail early on inputs the shipped RBAC and admission depend on. */}}
{{- define "konstapel.validate" -}}
{{- if ne .Release.Namespace "konstapel-system" -}}
{{- fail (printf "install the konstapel chart into the konstapel-system namespace (the generated RBAC and admission policies are scoped to it), not %q" .Release.Namespace) -}}
{{- end -}}
{{- if not .Values.image.digest -}}
{{- fail "image.digest is required: install a released chart (its packaging sets the verified digest) or set image.digest explicitly" -}}
{{- end -}}
{{- if ge (int .Values.controller.shutdownTimeoutSeconds) (int .Values.controller.terminationGracePeriodSeconds) -}}
{{- fail (printf "controller.shutdownTimeoutSeconds (%v) must be less than controller.terminationGracePeriodSeconds (%v)" .Values.controller.shutdownTimeoutSeconds .Values.controller.terminationGracePeriodSeconds) -}}
{{- end -}}
{{- if ge (int .Values.download.shutdownDrainSeconds) (int .Values.controller.terminationGracePeriodSeconds) -}}
{{- fail (printf "download.shutdownDrainSeconds (%v) must be less than controller.terminationGracePeriodSeconds (%v)" .Values.download.shutdownDrainSeconds .Values.controller.terminationGracePeriodSeconds) -}}
{{- end -}}
{{- if and (gt (int .Values.replicaCount) 1) .Values.podDisruptionBudget.enabled (ge (int .Values.podDisruptionBudget.minAvailable) (int .Values.replicaCount)) -}}
{{- fail (printf "podDisruptionBudget.minAvailable (%v) must be less than replicaCount (%v), or no voluntary eviction could ever proceed" .Values.podDisruptionBudget.minAvailable .Values.replicaCount) -}}
{{- end -}}
{{- if and .Values.download.enabled (gt (int .Values.download.replicaCount) 1) .Values.podDisruptionBudget.enabled (ge (int .Values.podDisruptionBudget.minAvailable) (int .Values.download.replicaCount)) -}}
{{- fail (printf "podDisruptionBudget.minAvailable (%v) must be less than download.replicaCount (%v), or no voluntary eviction could ever proceed" .Values.podDisruptionBudget.minAvailable .Values.download.replicaCount) -}}
{{- end -}}
{{- include "konstapel.validateBundles" . -}}
{{- include "konstapel.validateMetrics" . -}}
{{- end }}

{{- define "konstapel.downloadSelector" -}}
app.kubernetes.io/name: konstapel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: download
{{- end }}

{{/* The Secret holding the download server's tls.crt, tls.key, and ca.crt. */}}
{{- define "konstapel.downloadTLSSecret" -}}
{{- if eq .Values.tls.mode "secret" -}}
{{ .Values.tls.secret.name }}
{{- else -}}
konstapel-download-tls
{{- end -}}
{{- end }}

{{/*
OCI bundle values (docs/policy-bundles.md, "Controller wiring"). Nothing is
checked or rendered while bundles.sourcesConfigMap is empty, except that
access grants without the feature are refused.
*/}}
{{- define "konstapel.bundlesEnabled" -}}
{{- if (.Values.bundles | default dict).sourcesConfigMap -}}true{{- end -}}
{{- end }}

{{/* A schema-validated <n>Mi or <n>Gi quantity in MiB. */}}
{{- define "konstapel.mebibytes" -}}
{{- if hasSuffix "Gi" . -}}{{ mul (trimSuffix "Gi" . | int64) 1024 }}{{- else -}}{{ trimSuffix "Mi" . | int64 }}{{- end -}}
{{- end }}

{{- define "konstapel.validateBundles" -}}
{{- $b := .Values.bundles | default dict -}}
{{- if not (include "konstapel.bundlesEnabled" .) -}}
{{- if or $b.referencedSecrets $b.referencedConfigMaps -}}
{{- fail "bundles.referencedSecrets and bundles.referencedConfigMaps grant the controller access to objects only for OCI bundles: set bundles.sourcesConfigMap, or leave them empty" -}}
{{- end -}}
{{- else -}}
{{- if le (include "konstapel.mebibytes" $b.cache.sizeLimit | int64) (include "konstapel.mebibytes" $b.cache.capacity | int64) -}}
{{- fail (printf "bundles.cache.sizeLimit (%v) must be larger than bundles.cache.capacity (%v): the cache's block accounting only approximates disk use, and exceeding an emptyDir sizeLimit evicts the pod" $b.cache.sizeLimit $b.cache.capacity) -}}
{{- end -}}
{{- $refresh := $b.refreshInterval -}}
{{- $seconds := ternary (mul (trimSuffix "m" $refresh | int64) 60) (trimSuffix "s" $refresh | int64) (hasSuffix "m" $refresh) -}}
{{- if gt (int64 $seconds) 300 -}}
{{- fail (printf "bundles.refreshInterval (%v) must be at most 5m" $refresh) -}}
{{- end -}}
{{- if has $b.sourcesConfigMap $b.referencedConfigMaps -}}
{{- fail (printf "bundles.referencedConfigMaps must not list the sources ConfigMap %q: it is granted separately, and sources.yaml cannot reference itself" $b.sourcesConfigMap) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Authenticated controller metrics (docs/charts.md, "Controller metrics").
*/}}
{{- define "konstapel.validateMetrics" -}}
{{- $m := .Values.metrics -}}
{{- if and (not $m.enabled) $m.readers -}}
{{- fail "metrics.readers grants scrape access only to the metrics endpoint: set metrics.enabled, or leave metrics.readers empty" -}}
{{- end -}}
{{- if and $m.enabled (eq .Values.tls.mode "secret") (not $m.tls.secretName) -}}
{{- fail "metrics.tls.secretName is required with tls.mode=secret: a kubernetes.io/tls Secret with tls.crt, tls.key and ca.crt for konstapel-controller-metrics.<namespace>.svc" -}}
{{- end -}}
{{- include "konstapel.validateMonitoring" . -}}
{{- end }}

{{/* The Secret holding the metrics server's tls.crt, tls.key, and ca.crt. */}}
{{- define "konstapel.metricsTLSSecret" -}}
{{- if eq .Values.tls.mode "secret" -}}
{{ .Values.metrics.tls.secretName }}
{{- else -}}
konstapel-controller-metrics-tls
{{- end -}}
{{- end }}

{{- define "konstapel.durationSeconds" -}}
{{- if hasSuffix "m" . -}}{{ mul (trimSuffix "m" . | int64) 60 }}{{- else -}}{{ trimSuffix "s" . | int64 }}{{- end -}}
{{- end }}

{{/*
Optional Prometheus Operator integrations (docs/charts.md, "Monitoring
integration"). Both need metrics.enabled and, when enabled, their own API.
*/}}
{{- define "konstapel.validateMonitoring" -}}
{{- $m := .Values.metrics -}}
{{- $sm := $m.serviceMonitor -}}
{{- $pr := $m.prometheusRule -}}
{{- if and (or $sm.enabled $pr.enabled) (not $m.enabled) -}}
{{- fail "metrics.serviceMonitor and metrics.prometheusRule monitor the metrics endpoint: set metrics.enabled, or leave both disabled" -}}
{{- end -}}
{{- if and $sm.enabled (not (.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/ServiceMonitor")) -}}
{{- fail "metrics.serviceMonitor.enabled needs the monitoring.coreos.com/v1 ServiceMonitor API, which this cluster does not serve: install the Prometheus Operator CRDs (the chart never does), or disable it; offline helm template needs --api-versions monitoring.coreos.com/v1/ServiceMonitor" -}}
{{- end -}}
{{- if and $pr.enabled (not (.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/PrometheusRule")) -}}
{{- fail "metrics.prometheusRule.enabled needs the monitoring.coreos.com/v1 PrometheusRule API, which this cluster does not serve: install the Prometheus Operator CRDs (the chart never does), or disable it; offline helm template needs --api-versions monitoring.coreos.com/v1/PrometheusRule" -}}
{{- end -}}
{{- range $key, $labels := dict "metrics.serviceMonitor.labels" $sm.labels "metrics.prometheusRule.labels" $pr.labels -}}
{{- range $k, $_ := $labels -}}
{{- if hasPrefix "app.kubernetes.io/" $k -}}
{{- fail (printf "%s must not set %s: the chart owns the app.kubernetes.io labels that scope this release" $key $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $sm.enabled -}}
{{- $interval := include "konstapel.durationSeconds" $sm.interval | int64 -}}
{{- $timeout := include "konstapel.durationSeconds" $sm.scrapeTimeout | int64 -}}
{{- if ge $timeout $interval -}}
{{- fail (printf "metrics.serviceMonitor.scrapeTimeout (%s) must be shorter than metrics.serviceMonitor.interval (%s)" $sm.scrapeTimeout $sm.interval) -}}
{{- end -}}
{{- if gt $interval 120 -}}
{{- fail (printf "metrics.serviceMonitor.interval (%s) must be at most 2m: Prometheus marks series stale after 5m and the alert windows assume several scrapes" $sm.interval) -}}
{{- end -}}
{{- $ca := $sm.tls.ca | default dict -}}
{{- $set := list -}}
{{- if ($ca.secret | default dict).name -}}{{- $set = append $set "secret" -}}{{- end -}}
{{- if ($ca.configMap | default dict).name -}}{{- $set = append $set "configMap" -}}{{- end -}}
{{- if $ca.file -}}{{- $set = append $set "file" -}}{{- end -}}
{{- if gt (len $set) 1 -}}
{{- fail (printf "metrics.serviceMonitor.tls.ca sets %s: choose one CA source" (join ", " $set)) -}}
{{- end -}}
{{- $az := $sm.authorization -}}
{{- if and (eq $az.mode "secret") (not ($az.secret | default dict).name) -}}
{{- fail "metrics.serviceMonitor.authorization.secret.name is required with authorization.mode=secret" -}}
{{- end -}}
{{- if and (eq $az.mode "serviceAccountToken") ($az.secret | default dict).name -}}
{{- fail "metrics.serviceMonitor.authorization.secret.name conflicts with authorization.mode=serviceAccountToken: set mode=secret to use the Secret" -}}
{{- end -}}
{{- end -}}
{{- if $pr.enabled -}}
{{- range $gname, $g := $pr.groups -}}
{{- range $rname, $r := $g.rules -}}
{{- if and (ne ($r.enabled | toString) "false") -}}
{{- if not $r.expr -}}
{{- fail (printf "metrics.prometheusRule.groups.%s.rules.%s has no expr" $gname $rname) -}}
{{- end -}}
{{- if and (contains "__threshold__" $r.expr) (not (hasKey $r "threshold")) -}}
{{- fail (printf "metrics.prometheusRule.groups.%s.rules.%s.expr uses __threshold__ but sets no threshold" $gname $rname) -}}
{{- end -}}
{{- range $k, $_ := ($r.labels | default dict) -}}
{{- if or (eq $k "severity") (eq $k "alertname") -}}
{{- fail (printf "metrics.prometheusRule.groups.%s.rules.%s.labels must not set %s: use the severity field" $gname $rname $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* Exact label matchers selecting this release's scraped series. */}}
{{- define "konstapel.metricsScope" -}}
{{- $pr := .Values.metrics.prometheusRule -}}
{{- $m := dict -}}
{{- if $pr.scope.matchers -}}
{{- $m = $pr.scope.matchers -}}
{{- else -}}
{{- $m = dict "job" "konstapel-controller-metrics" "namespace" .Release.Namespace -}}
{{- if .Values.metrics.serviceMonitor.enabled -}}
{{- $_ := set $m "app_kubernetes_io_instance" .Release.Name -}}
{{- end -}}
{{- end -}}
{{- $parts := list -}}
{{- range $k := keys $m | sortAlpha -}}
{{- $parts = append $parts (printf "%s=%s" $k (get $m $k | toJson)) -}}
{{- end -}}
{{- join "," $parts -}}
{{- end }}
