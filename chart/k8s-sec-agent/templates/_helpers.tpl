{{/*
Fullname — used for all resource names.
*/}}
{{- define "k8s-sec-agent.fullname" -}}
{{- default .Chart.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Service name (MCP + proxy deployment/service).
*/}}
{{- define "k8s-sec-agent.serviceName" -}}
{{ include "k8s-sec-agent.fullname" . }}-service
{{- end }}

{{/*
Common labels.
*/}}
{{- define "k8s-sec-agent.labels" -}}
app.kubernetes.io/name: {{ include "k8s-sec-agent.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Selector labels for the service deployment.
*/}}
{{- define "k8s-sec-agent.serviceSelector" -}}
app: {{ include "k8s-sec-agent.serviceName" . }}
{{- end }}

{{/*
Internal service URL for the proxy (used by ModelConfig).
*/}}
{{- define "k8s-sec-agent.proxyUrl" -}}
http://{{ include "k8s-sec-agent.serviceName" . }}.{{ .Release.Namespace }}:{{ .Values.service.port }}/v1
{{- end }}

{{/*
Internal service URL for the MCP endpoint.
*/}}
{{- define "k8s-sec-agent.mcpUrl" -}}
http://{{ include "k8s-sec-agent.serviceName" . }}.{{ .Release.Namespace }}:{{ .Values.service.port }}/mcp
{{- end }}
