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
