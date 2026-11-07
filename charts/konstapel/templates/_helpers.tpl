{{/*
Runtime templates (Deployment, Services, RBAC, webhooks, certificates) are
added from the merged owners' inputs listed in docs/charts.md; until then the
chart renders nothing, so it can never deploy a crash-looping prototype.
*/}}
{{- define "konstapel.labels" -}}
app.kubernetes.io/name: konstapel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: konstapel
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
