{{/* SPDX-License-Identifier: Apache-2.0 */}}

{{/*
The checks of values.schema.json that protect something are made here a
second time, so that they also hold when the schema is not applied.
*/}}

{{- define "pgsnare.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pgsnare.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "pgsnare.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pgsnare.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "pgsnare.labels" -}}
{{ include "pgsnare.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | quote }}
{{- end -}}

{{/*
The image, by digest and by nothing else. A tag can be moved to another
image, so a repository with a tag is refused, and so is a missing digest.
*/}}
{{- define "pgsnare.image" -}}
{{- $repository := toString .Values.image.repository -}}
{{- $digest := toString .Values.image.digest -}}
{{- if not (regexMatch "^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$" $repository) -}}
{{- fail "image.repository must be a registry and a path, without a tag and without a digest" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail "image.digest is required, as sha256: and 64 hexadecimal digits: the image is named by digest only" -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- end -}}

{{/* Where the Secrets named in the values are mounted, each as a whole volume. */}}
{{- define "pgsnare.secretsDirectory" -}}
/etc/pgsnare-secrets
{{- end -}}

{{/* The port of the admin listener. It stays on loopback and has no setting. */}}
{{- define "pgsnare.adminPort" -}}
9641
{{- end -}}

{{/*
The peers of one NetworkPolicy rule, from a list of the values.

  root    the root context
  peers   the list
  path    the name of the list, for messages
  pods    true when only pods may be named: no address range

An item names pods by a namespace and at least one label, or it names a
range of addresses. It is always rendered with both selectors in one item,
which means pods with these labels in that namespace. An item without a
label is refused: an empty selector would mean every pod. A range with a
prefix of 0, which is every address, is refused too.

A caller renders no rule at all when its list is empty: a rule without
peers would allow everybody.
*/}}
{{- define "pgsnare.peers" -}}
{{- $root := .root -}}
{{- $path := .path -}}
{{- $podsOnly := .pods -}}
{{- range $index, $peer := .peers -}}
{{- $here := printf "%s[%d]" $path $index -}}
{{- if not (kindIs "map" $peer) -}}
{{- fail (printf "%s: a peer is a mapping with podLabels or with cidr" $here) -}}
{{- end -}}
{{- if hasKey $peer "cidr" -}}
{{- if $podsOnly -}}
{{- fail (printf "%s: only pods can be named here, by podLabels" $here) -}}
{{- end -}}
{{- if or (hasKey $peer "podLabels") (hasKey $peer "namespace") -}}
{{- fail (printf "%s: a peer is either pods or a range of addresses, not both" $here) -}}
{{- end -}}
{{- if not (regexMatch "^(([0-9]{1,3}\\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|3[0-2])|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]{1,37}/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))$" (toString $peer.cidr)) -}}
{{- fail (printf "%s: cidr must be an address range with a prefix of at least 1" $here) -}}
{{- end }}
- ipBlock:
    cidr: {{ $peer.cidr | quote }}
{{- else -}}
{{- if or (not (kindIs "map" $peer.podLabels)) (not $peer.podLabels) -}}
{{- fail (printf "%s: podLabels needs at least one label; without one, every pod would be meant" $here) -}}
{{- end -}}
{{- $namespace := default $root.Release.Namespace $peer.namespace | toString -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" $namespace) -}}
{{- fail (printf "%s: namespace must be the name of one namespace" $here) -}}
{{- end }}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ $namespace | quote }}
  podSelector:
    matchLabels:
      {{- range $key, $value := $peer.podLabels }}
      {{ $key | quote }}: {{ $value | toString | quote }}
      {{- end }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The egress rules for the receivers of the webhooks: one rule for each
webhook that names where its receiver is, and none for one that does not.
*/}}
{{- define "pgsnare.webhookEgress" -}}
{{- range $index, $webhook := .Values.sinks.webhooks }}
{{- $receiver := include "pgsnare.peers" (dict "root" $ "peers" $webhook.peers "path" (printf "sinks.webhooks[%d].peers" $index) "pods" false) | trim }}
{{- if $receiver }}
# The receiver of webhook {{ $index }}.
- to:
    {{- $receiver | nindent 4 }}
  ports:
    - protocol: TCP
      port: {{ int (default 443 $webhook.port) }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Seconds the cluster gives a pod to stop: see the Deployment. */}}
{{- define "pgsnare.terminationGracePeriodSeconds" -}}
{{- add (int .Values.shutdown.preStopSleepSeconds) (int .Values.shutdown.gracePeriodSeconds) 5 -}}
{{- end -}}

{{/* Checks across values. Rendered by the ConfigMap; prints nothing. */}}
{{- define "pgsnare.validate" -}}
{{- $admin := include "pgsnare.adminPort" . | int -}}
{{- $proxy := int .Values.proxy.port -}}
{{- $metrics := int .Values.metrics.port -}}
{{- if not .Values.database.host -}}
{{- fail "database.host is required" -}}
{{- end -}}
{{- if not .Values.tokens.secretNames -}}
{{- fail "tokens.secretNames is required: at least one existing Secret with honeytoken files" -}}
{{- end -}}
{{- if and (not .Values.sinks.stdout) (not .Values.sinks.webhooks) -}}
{{- fail "at least one sink is required: sinks.stdout or an item in sinks.webhooks" -}}
{{- end -}}
{{- if or (lt $proxy 1024) (gt $proxy 65535) -}}
{{- fail "proxy.port must be between 1024 and 65535" -}}
{{- end -}}
{{- if eq $proxy $admin -}}
{{- fail (printf "proxy.port must not be %d, the port of the admin listener" $admin) -}}
{{- end -}}
{{- if .Values.metrics.scrapers -}}
{{- if or (lt $metrics 1024) (gt $metrics 65535) -}}
{{- fail "metrics.port must be between 1024 and 65535" -}}
{{- end -}}
{{- if or (eq $metrics $admin) (eq $metrics $proxy) -}}
{{- fail "metrics.port must differ from proxy.port and from the port of the admin listener" -}}
{{- end -}}
{{- else if eq $proxy 9642 -}}
{{- fail "proxy.port must not be 9642, where the metrics listen on loopback" -}}
{{- end -}}
{{- $clientTLS := .Values.proxy.clientTLS -}}
{{- if and (ne $clientTLS.mode "disable") (not $clientTLS.secretName) -}}
{{- fail "proxy.clientTLS.secretName is required unless proxy.clientTLS.mode is disable" -}}
{{- end -}}
{{- if and (eq $clientTLS.mode "disable") $clientTLS.secretName -}}
{{- fail "proxy.clientTLS.secretName is set but proxy.clientTLS.mode is disable: remove one" -}}
{{- end -}}
{{- $databaseTLS := .Values.database.tls -}}
{{- if and $databaseTLS.caSecretName (ne $databaseTLS.mode "verify-full") -}}
{{- fail "database.tls.caSecretName is only used with mode verify-full: no other mode verifies the certificate" -}}
{{- end -}}
{{- if and $databaseTLS.serverName (eq $databaseTLS.mode "disable") -}}
{{- fail "database.tls.serverName is set but database.tls.mode is disable: remove one" -}}
{{- end -}}
{{- end -}}

{{/*
The configuration file. It names files and never holds a secret: token
files, keys, the address of a webhook and its signing key are read from
the mounted Secrets.

It has no `admin` section, so the admin listener stays on its default, the
loopback address. The metrics listener leaves loopback only when scrapers
are listed.
*/}}
{{- define "pgsnare.config" -}}
{{- $secrets := include "pgsnare.secretsDirectory" . -}}

{{- $clientTLS := dict "mode" .Values.proxy.clientTLS.mode -}}
{{- if ne .Values.proxy.clientTLS.mode "disable" -}}
{{- $_ := set $clientTLS "cert" (printf "%s/client-tls/tls.crt" $secrets) -}}
{{- $_ := set $clientTLS "key" (printf "%s/client-tls/tls.key" $secrets) -}}
{{- end -}}
{{- with .Values.proxy.clientTLS.minVersion -}}
{{- $_ := set $clientTLS "min_version" . -}}
{{- end -}}

{{- $upstreamTLS := dict "mode" .Values.database.tls.mode -}}
{{- if .Values.database.tls.caSecretName -}}
{{- $_ := set $upstreamTLS "ca" (printf "%s/database-ca/ca.crt" $secrets) -}}
{{- end -}}
{{- with .Values.database.tls.serverName -}}
{{- $_ := set $upstreamTLS "server_name" . -}}
{{- end -}}
{{- with .Values.database.tls.minVersion -}}
{{- $_ := set $upstreamTLS "min_version" . -}}
{{- end -}}

{{- $host := toString .Values.database.host -}}
{{- if contains ":" $host -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- $listener := dict
    "name" "main"
    "listen" (printf "0.0.0.0:%d" (int .Values.proxy.port))
    "upstream" (printf "%s:%d" $host (int .Values.database.port))
    "client_tls" $clientTLS
    "upstream_tls" $upstreamTLS -}}
{{- if .Values.proxy.maxConnections -}}
{{- $_ := set $listener "max_connections" (int .Values.proxy.maxConnections) -}}
{{- end -}}
{{- with .Values.proxy.loginTimeout -}}
{{- $_ := set $listener "login_timeout" . -}}
{{- end -}}

{{- $tokenFiles := list -}}
{{- range $index, $name := .Values.tokens.secretNames -}}
{{- $tokenFiles = append $tokenFiles (printf "%s/tokens-%d/*.yaml" $secrets $index) -}}
{{- end -}}

{{- $sinks := list -}}
{{- if .Values.sinks.stdout -}}
{{- $sinks = append $sinks (dict "type" "stdout") -}}
{{- end -}}
{{- range $index, $webhook := .Values.sinks.webhooks -}}
{{- $sink := dict
    "type" "webhook"
    "url_file" (printf "%s/webhook-%d/url" $secrets $index)
    "hmac_secret_file" (printf "%s/webhook-%d/hmac-secret" $secrets $index) -}}
{{- range $key := list "timeout" "max_retries" "queue_size" "max_events_per_second" -}}
{{- if hasKey (default dict $webhook.config) $key -}}
{{- $_ := set $sink $key (get $webhook.config $key) -}}
{{- end -}}
{{- end -}}
{{- $sinks = append $sinks $sink -}}
{{- end -}}

{{- $settings := default dict .Values.config -}}
{{- $events := dict -}}
{{- range $key := list "query_redaction" "dedup_window" "queue_size" "labels" -}}
{{- if hasKey (default dict $settings.events) $key -}}
{{- $_ := set $events $key (get $settings.events $key) -}}
{{- end -}}
{{- end -}}
{{- $_ := set $events "labels_from_env" (list "POD_NAME" "POD_NAMESPACE") -}}
{{- $_ := set $events "sinks" $sinks -}}

{{- $config := dict
    "listeners" (list $listener)
    "token_files" $tokenFiles
    "events" $events
    "shutdown" (dict "grace_period" (printf "%ds" (int .Values.shutdown.gracePeriodSeconds))) -}}

{{- $inspection := dict -}}
{{- range $key := list "on_error" "max_buffered_frame" -}}
{{- if hasKey (default dict $settings.inspection) $key -}}
{{- $_ := set $inspection $key (get $settings.inspection $key) -}}
{{- end -}}
{{- end -}}
{{- if $inspection -}}
{{- $_ := set $config "inspection" $inspection -}}
{{- end -}}

{{- $exemptions := list -}}
{{- range $index, $given := $settings.exemptions -}}
{{- $exemption := dict -}}
{{- range $key := list "db_user" "client_cidr" -}}
{{- if hasKey $given $key -}}
{{- $_ := set $exemption $key (get $given $key) -}}
{{- end -}}
{{- end -}}
{{- if not $exemption -}}
{{- fail (printf "config.exemptions[%d]: an exemption names db_user, client_cidr or both" $index) -}}
{{- end -}}
{{- $exemptions = append $exemptions $exemption -}}
{{- end -}}
{{- if $exemptions -}}
{{- $_ := set $config "exemptions" $exemptions -}}
{{- end -}}

{{- $actions := dict -}}
{{- range $action, $keys := dict
    "kill" (list "sqlstate" "message")
    "tarpit" (list "delay" "max_duration" "max_sessions" "max_bytes_per_second")
    "fake_data" (list "rows") -}}
{{- $chosen := dict -}}
{{- range $key := $keys -}}
{{- if hasKey (default dict (get (default dict $settings.actions) $action)) $key -}}
{{- $_ := set $chosen $key (get (get $settings.actions $action) $key) -}}
{{- end -}}
{{- end -}}
{{- if $chosen -}}
{{- $_ := set $actions $action $chosen -}}
{{- end -}}
{{- end -}}
{{- if $actions -}}
{{- $_ := set $config "actions" $actions -}}
{{- end -}}

{{- if .Values.metrics.scrapers -}}
{{- $_ := set $config "metrics" (dict "listen" (printf "0.0.0.0:%d" (int .Values.metrics.port))) -}}
{{- end -}}

{{- toYaml $config -}}
{{- end -}}
