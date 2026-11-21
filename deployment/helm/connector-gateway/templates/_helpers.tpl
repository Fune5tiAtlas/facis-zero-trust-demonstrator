{{- define "gateway.validate" -}}
{{- $v := .Values -}}
{{- if eq $v.egress.enabled $v.ingress.enabled -}}{{ fail "exactly one of egress.enabled and ingress.enabled: a release is one role" }}{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $v.image.digest) -}}{{ fail "image.digest must be a sha256 digest" }}{{- end -}}
{{- if hasKey $v.podAnnotations "proxy.istio.io/config" -}}{{ fail "podAnnotations: proxy.istio.io/config is refused at admission in a plane namespace (zone-policy)" }}{{- end -}}
{{- if $v.egress.enabled -}}
{{- if not $v.trustDomain -}}{{ fail "trustDomain is required for the egress role" }}{{- end -}}
{{- if empty $v.egress.callers -}}{{ fail "egress.callers: at least one caller" }}{{- end -}}
{{- range $v.egress.callers -}}
{{- if or (not .serviceAccount) (empty .podSelector) -}}{{ fail "every egress caller needs serviceAccount and podSelector" }}{{- end -}}
{{- end -}}
{{- $p := $v.egress.peer -}}
{{- if not $p.name -}}{{ fail "egress.peer.name is required" }}{{- end -}}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}$" $p.address) -}}{{ fail "egress.peer.address must be the peer entry's IPv4 address" }}{{- end -}}
{{- if not (contains "BEGIN CERTIFICATE" $p.caCert) -}}{{ fail "egress.peer.caCert must hold the PEM CA certificate of the peer entry" }}{{- end -}}
{{- end -}}
{{- if $v.ingress.enabled -}}
{{- if or (not $v.ingress.tlsSecret) (not $v.ingress.upstream.name) (empty $v.ingress.sourceRanges) -}}{{ fail "ingress.tlsSecret, ingress.upstream.name and ingress.sourceRanges are required" }}{{- end -}}
{{- end -}}
{{- end -}}

{{/* The subject alternative name checked on the peer entry's certificate. */}}
{{- define "gateway.peerName" -}}{{ default .Values.egress.peer.address .Values.egress.peer.serverName }}{{- end -}}

{{/* One JSON line per request on stdout: the record that application traffic crossed the zone boundary
here. No credential, body or header beyond these is logged. */}}
{{- define "gateway.accessLog" -}}
access_log:
  - name: envoy.access_loggers.stdout
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        json_format:
          time: "%START_TIME%"
          role: {{ . | quote }}
          method: "%REQ(:METHOD)%"
          path: "%REQ(:PATH)%"
          status: "%RESPONSE_CODE%"
          flags: "%RESPONSE_FLAGS%"
          upstream: "%UPSTREAM_HOST%"
          user_agent: "%REQ(USER-AGENT)%"
          request_id: "%REQ(X-REQUEST-ID)%"
{{- end -}}
