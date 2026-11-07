{{/*
Generated CRDs are added by the CRD packaging step (add-helm-oci-distribution
group 2) from config/crd/bases; this chart never carries hand-written or
placeholder definitions.
*/}}
{{- define "konstapel-crds.labels" -}}
app.kubernetes.io/name: konstapel-crds
app.kubernetes.io/part-of: konstapel
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
