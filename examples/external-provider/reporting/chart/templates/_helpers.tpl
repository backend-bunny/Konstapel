{{/*
The example reporting provider's reference chart
(docs/integration/external-provider-chart.md): a source worker and an
evaluator with separate ServiceAccounts, each Service named after its
component. Names stay short enough for DNS labels with a component suffix.
*/}}
{{- define "reporting.fullname" -}}
{{- if contains "example-reporting" .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-example-reporting" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{- define "reporting.labels" -}}
app.kubernetes.io/name: example-reporting-provider
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{/* Stable selector of one component: worker or evaluator. */}}
{{- define "reporting.selector" -}}
app.kubernetes.io/name: example-reporting-provider
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "reporting.worker" -}}{{ include "reporting.fullname" . }}-worker{{- end }}
{{- define "reporting.evaluator" -}}{{ include "reporting.fullname" . }}-evaluator{{- end }}

{{- define "reporting.workerClientName" -}}
{{- .Values.worker.clientName | default (printf "%s.%s.svc" (include "reporting.worker" .) .Release.Namespace) -}}
{{- end }}
{{- define "reporting.evaluatorServerName" -}}
{{- .Values.evaluator.serverName | default (printf "%s.%s.svc" (include "reporting.evaluator" .) .Release.Namespace) -}}
{{- end }}

{{- define "reporting.workerSecret" -}}{{ .Values.tls.workerSecretName | default (printf "%s-tls" (include "reporting.worker" .)) }}{{- end }}
{{- define "reporting.workerClientSecret" -}}{{ .Values.tls.workerClientSecretName | default (printf "%s-client-tls" (include "reporting.worker" .)) }}{{- end }}
{{- define "reporting.evaluatorSecret" -}}{{ .Values.tls.evaluatorSecretName | default (printf "%s-tls" (include "reporting.evaluator" .)) }}{{- end }}

{{/* The image, by digest only. */}}
{{- define "reporting.image" -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- end }}

{{/* Inputs the deployments cannot run without. */}}
{{- define "reporting.validate" -}}
{{- if not .Values.image.digest -}}
{{- fail "image.digest is required: pin the verified provider image by its sha256 digest; tags are not accepted" -}}
{{- end -}}
{{- if not .Values.worker.authorizedHosts -}}
{{- fail "worker.authorizedHosts is required: name the host identities (client certificate DNS SANs) allowed to call the provider" -}}
{{- end -}}
{{- if and .Values.evaluator.authorizedHosts (not .Values.evaluator.hostNamespaces) -}}
{{- fail "evaluator.authorizedHosts needs evaluator.hostNamespaces: the evaluator's NetworkPolicy admits only the worker otherwise" -}}
{{- end -}}
{{- if has (include "reporting.workerClientName" .) .Values.evaluator.authorizedHosts -}}
{{- fail "evaluator.authorizedHosts must not repeat the worker's client identity, which the evaluator always authorizes" -}}
{{- end -}}
{{- if eq (int .Values.ports.protocol) (int .Values.ports.health) -}}
{{- fail "ports.protocol and ports.health must differ: probes never use the protocol port" -}}
{{- end -}}
{{- end }}

{{/*
The container and pod security settings both deployments share: non-root,
no privilege escalation, no capabilities, a read-only root filesystem.
*/}}
{{- define "reporting.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}
{{- define "reporting.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}

{{- define "reporting.probes" -}}
readinessProbe:
  httpGet: {path: /readyz, port: health}
  periodSeconds: 5
livenessProbe:
  httpGet: {path: /healthz, port: health}
  periodSeconds: 10
{{- end }}
