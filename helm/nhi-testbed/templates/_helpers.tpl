{{/*
Expand the name of the chart.
*/}}
{{- define "nhi-testbed.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "nhi-testbed.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nhi-testbed.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "nhi-testbed.labels" -}}
helm.sh/chart: {{ include "nhi-testbed.chart" . }}
{{ include "nhi-testbed.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nhi-testbed
{{- end }}

{{/*
Selector labels used for matching pods to services and deployments.
*/}}
{{- define "nhi-testbed.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nhi-testbed.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve image reference with optional global registry prefix.
Usage: {{ include "nhi-testbed.image" (dict "image" .Values.path.to.image "global" .Values.global) }}
*/}}
{{- define "nhi-testbed.image" -}}
{{- $registry := .global.imageRegistry | default "" -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry .image.repository (.image.tag | default "latest") }}
{{- else }}
{{- printf "%s:%s" .image.repository (.image.tag | default "latest") }}
{{- end }}
{{- end }}

{{/*
Return the target namespace.
*/}}
{{- define "nhi-testbed.namespace" -}}
{{- .Values.namespace.name | default "nhi-testbed" }}
{{- end }}

{{/*
Create a component-specific fullname.
Usage: {{ include "nhi-testbed.componentName" (list . "manager") }}
*/}}
{{- define "nhi-testbed.componentName" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s-%s" (include "nhi-testbed.fullname" $root) $component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Network tier label for a given tier name.
Usage: {{ include "nhi-testbed.networkTier" "mgmt" }}
*/}}
{{- define "nhi-testbed.networkTier" -}}
nhi.network/tier: {{ . }}
{{- end }}
