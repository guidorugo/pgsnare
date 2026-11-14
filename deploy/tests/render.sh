#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Renders the chart and checks what comes out, and what is refused.
#
#   deploy/tests/render.sh [BINARY]
#
# It needs `helm` and `kubeconform` on the path, both from
# deploy/tools/tools.txt, and no cluster. With BINARY, a pgsnare binary,
# every configuration file the chart renders is also given to
# `pgsnare config check`.
#
# What it does:
#
#   1. For each file of deploy/chart/pgsnare/ci/: `helm lint --strict`, a
#      rendering, a strict validation of the manifests against the schemas
#      of one Kubernetes version, and the rules that hold for every
#      rendering: the image by digest, no Secret, the restricted pod, no
#      NetworkPolicy rule without peers, and so on.
#   2. Renderings whose outcome depends on a value: an empty list of
#      clients gives no ingress rule and a list with one client gives one.
#   3. Refusals: an unknown value, a missing digest, a token value and a
#      selector that would mean everybody each fail, by the schema and, for
#      what protects something, by the templates when the schema is not
#      applied.
#
# A check that passes proves little unless it can fail. So every refusal
# starts from values that render, and differs from them in one setting;
# every count of "none" has a rendering next to it where the count is not
# zero; and the validator is shown a manifest with a field that does not
# exist, which it must reject.
#
# Every failure is reported, and the script then exits with status 1.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
chart="$root/deploy/chart/pgsnare"
binary="${1:-}"

# The Kubernetes version the manifests are validated against: the one of
# the node image in deploy/tests/kubernetes/kind.yaml.
kubernetes_version="1.37.0"
# The schemas of that version, from one commit of the collection the
# validator uses, so that they cannot change under the test.
schemas_commit="2bfaff3898a7a4fa4e4760da3d2656211c9b4c71"
schema_location="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$schemas_commit/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json"

release="pgsnare"
namespace="pgsnare-render"
minimal="$chart/ci/minimal.yaml"

for tool in helm kubeconform; do
    command -v "$tool" >/dev/null || { echo "render: $tool is not on the path" >&2; exit 1; }
done
if [[ -n "$binary" && ! -x "$binary" ]]; then
    echo "render: $binary is not a program" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
checks=0

fail() {
    failures=$((failures + 1))
    echo "render: FAILED: $*" >&2
}

passed() {
    checks=$((checks + 1))
}

# --- Helpers ----------------------------------------------------------------

# render OUT ARGUMENT...: the manifests in OUT, the messages in OUT.err.
render() {
    local out="$1"
    shift
    helm template "$release" "$chart" --namespace "$namespace" \
        --kube-version "$kubernetes_version" "$@" > "$out" 2> "$out.err"
}

# document FILE KIND: the one document of that kind.
document() {
    awk -v kind="$2" '
        function flush() { if (found) printf "%s", text; text = ""; found = 0 }
        /^---[[:space:]]*$/ { flush(); next }
        { text = text $0 "\n" }
        $0 == "kind: " kind { found = 1 }
        END { flush() }
    ' "$1"
}

# count FILE PATTERN: the number of lines that match.
count() {
    grep -c -E -- "$2" "$1" || true
}

# number N: a pattern for N as a number of its own, and not as a part of a
# checksum.
number() {
    echo "(^|[^0-9a-f])$1([^0-9a-f]|\$)"
}

# expect WHAT FILE NUMBER PATTERN: exactly that many lines match.
expect() {
    local what="$1" file="$2" number="$3" pattern="$4" found
    found="$(count "$file" "$pattern")"
    if [[ "$found" -eq "$number" ]]; then
        passed
    else
        fail "$what: $found lines match '$pattern', expected $number"
    fi
}

# accepted WHAT ARGUMENT...: the values render.
accepted() {
    local what="$1"
    shift
    if render "$work/accepted.yaml" "$@"; then
        passed
    else
        fail "$what: refused, but it must render: $(head -c 400 "$work/accepted.yaml.err" | tr '\n' ' ')"
    fi
}

# refused WHAT PATTERN ARGUMENT...: the values do not render, and the
# message matches PATTERN.
refused() {
    local what="$1" pattern="$2"
    shift 2
    if render "$work/refused.yaml" "$@"; then
        fail "$what: rendered, but it must be refused"
    elif ! tr '\n' ' ' < "$work/refused.yaml.err" | grep -q -i -E -- "$pattern"; then
        fail "$what: refused, but not for the expected reason '$pattern': $(head -c 400 "$work/refused.yaml.err" | tr '\n' ' ')"
    else
        passed
    fi
}

# by_schema and by_templates: a refusal from values.schema.json, and one
# from the templates when the schema is not applied.
by_schema() {
    local what="$1" pattern="$2"
    shift 2
    refused "$what (schema)" "schema.*$pattern" --values "$minimal" "$@"
}

by_templates() {
    local what="$1" pattern="$2"
    shift 2
    refused "$what (templates)" "execution error.*$pattern" --values "$minimal" --skip-schema-validation "$@"
}

validate() {
    kubeconform -strict -summary -kubernetes-version "$kubernetes_version" \
        -schema-location "$schema_location" "$1"
}

# --- The rules for every rendering -------------------------------------------

rules() {
    local name="$1" file="$2" kind

    for kind in ConfigMap Deployment NetworkPolicy PodDisruptionBudget Service ServiceAccount; do
        expect "$name: one $kind" "$file" 1 "^kind: $kind\$"
    done
    expect "$name: six objects and no other" "$file" 6 '^kind: '
    expect "$name: no Secret is rendered" "$file" 0 '^kind: Secret'

    document "$file" Deployment > "$work/deployment.yaml"
    document "$file" NetworkPolicy > "$work/networkpolicy.yaml"
    document "$file" Service > "$work/service.yaml"
    document "$file" ConfigMap > "$work/configmap.yaml"
    document "$file" ServiceAccount > "$work/serviceaccount.yaml"

    # The image: one, by digest.
    expect "$name: one image" "$file" 1 '^[[:space:]]*(-[[:space:]]+)?image:'
    expect "$name: the image is named by digest" "$file" 1 \
        '^[[:space:]]*image: "[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}"$'

    # Secrets: whole volumes, as files for the group, never in the
    # environment.
    expect "$name: no subPath" "$file" 0 'subPath'
    expect "$name: no secret in the environment" "$file" 0 'secretKeyRef|envFrom|configMapKeyRef'
    local volumes
    volumes="$(count "$work/deployment.yaml" '^          (secret|configMap):$')"
    expect "$name: every volume has mode 0440" "$work/deployment.yaml" "$volumes" '^            defaultMode: 288$'
    expect "$name: no other mode" "$work/deployment.yaml" "$volumes" 'defaultMode:'
    expect "$name: every volume is mounted" "$work/deployment.yaml" "$volumes" '^              mountPath: '
    expect "$name: every mount is read-only" "$work/deployment.yaml" "$volumes" '^              readOnly: true$'
    expect "$name: no volume of another kind" "$work/deployment.yaml" 0 'emptyDir|persistentVolumeClaim|projected:'
    expect "$name: the group of the files" "$work/deployment.yaml" 1 '^        fsGroup: 65532$'

    # The pod: the restricted standard and more.
    expect "$name: not root" "$work/deployment.yaml" 2 '^ +runAsNonRoot: true$'
    expect "$name: a numeric user" "$work/deployment.yaml" 1 '^        runAsUser: 65532$'
    expect "$name: the default seccomp profile" "$work/deployment.yaml" 1 '^          type: RuntimeDefault$'
    expect "$name: no privilege escalation" "$work/deployment.yaml" 1 '^            allowPrivilegeEscalation: false$'
    expect "$name: a read-only root filesystem" "$work/deployment.yaml" 1 '^            readOnlyRootFilesystem: true$'
    expect "$name: all capabilities dropped" "$work/deployment.yaml" 1 '^                - ALL$'
    expect "$name: no capability added" "$file" 0 '^ +add:'
    expect "$name: nothing of the host" "$file" 0 'hostNetwork|hostPort|hostPID|hostIPC|hostPath|privileged: true'
    expect "$name: no token in the pod" "$work/deployment.yaml" 1 '^      automountServiceAccountToken: false$'
    expect "$name: no token from the account" "$work/serviceaccount.yaml" 1 '^automountServiceAccountToken: false$'
    expect "$name: no role" "$file" 0 '^kind: .*(Role|Binding)'
    expect "$name: requests" "$work/deployment.yaml" 1 '^            requests:$'
    expect "$name: limits" "$work/deployment.yaml" 1 '^            limits:$'
    expect "$name: a value for each" "$work/deployment.yaml" 4 '^              (cpu|memory): "[0-9][0-9A-Za-z.]*"$'

    # Probes: the binary, without a configuration file. The only --config
    # is the one of `run`.
    expect "$name: three probes run the health check" "$work/deployment.yaml" 3 '^                - healthcheck$'
    expect "$name: one of them asks for readiness" "$work/deployment.yaml" 1 '^                - --ready$'
    expect "$name: no probe reads a configuration" "$work/deployment.yaml" 1 '--config'
    expect "$name: no probe over the network" "$work/deployment.yaml" 0 'httpGet|tcpSocket|grpc:'

    # The admin listener: no setting, no port, nowhere.
    expect "$name: the admin port is named nowhere" "$file" 0 "$(number 9641)"
    expect "$name: the configuration has no admin section" "$work/configmap.yaml" 0 '^    admin:'
    expect "$name: no plain HTTP for a webhook" "$file" 0 'allow_insecure_http'

    # The Service: inside the cluster, and the proxy port alone.
    expect "$name: the Service is ClusterIP" "$work/service.yaml" 1 '^  type: ClusterIP$'
    expect "$name: the Service has one port" "$work/service.yaml" 1 '^      port: '
    expect "$name: no other kind of Service" "$file" 0 'NodePort|LoadBalancer|externalIPs|ExternalName'

    # The NetworkPolicy: both directions, and no rule or selector that
    # would mean everybody.
    expect "$name: the policy covers ingress" "$work/networkpolicy.yaml" 1 '^    - Ingress$'
    expect "$name: the policy covers egress" "$work/networkpolicy.yaml" 1 '^    - Egress$'
    expect "$name: no empty selector or rule" "$work/networkpolicy.yaml" 0 '\{\}|^ +- *$|(from|to|ports|matchLabels|podSelector|namespaceSelector|ipBlock): *(\[\]|null|~)$'
    expect "$name: no rule without ports" "$work/networkpolicy.yaml" \
        "$(count "$work/networkpolicy.yaml" '^    - (from|to):$')" '^      ports:$'
    if awk '
        # After `from:` or `to:` comes a peer. A peer names one namespace
        # and at least one label of the pods, or a range of addresses.
        function bad(why) { print FILENAME ":" NR ": " why; wrong = 1 }
        need == "peer" && !/^        - (namespaceSelector|ipBlock):$/ { bad("a rule without a peer") }
        need == "labels" && !/^            matchLabels:$/ { bad("a selector without matchLabels") }
        need == "namespace" && !/^              kubernetes\.io\/metadata\.name: "[a-z0-9-]+"$/ { bad("a namespace selector that is not one name") }
        need == "pods" && !/^          podSelector:$/ { bad("a namespace without a pod selector") }
        need == "podlabels" && !/^            matchLabels:$/ { bad("a pod selector without matchLabels") }
        need == "label" && !/^              "[^"]+": "[^"]*"$/ { bad("a pod selector without a label") }
        need == "cidr" && (!/^            cidr: "[0-9A-Fa-f:.]+\/[0-9]+"$/ || /\/0"$/) { bad("an address range that is none or is everything") }
        {
            previous = need
            need = ""
            if (/^    - (from|to):$/) need = "peer"
            else if (/^        - namespaceSelector:$/) need = "labels"
            else if (previous == "labels") need = "namespace"
            else if (previous == "namespace") need = "pods"
            else if (previous == "pods") need = "podlabels"
            else if (previous == "podlabels") need = "label"
            else if (/^        - ipBlock:$/) need = "cidr"
        }
        END { if (need != "") { print FILENAME ": ends inside a rule"; wrong = 1 } exit wrong }
    ' "$work/networkpolicy.yaml" >&2; then
        passed
    else
        fail "$name: the NetworkPolicy has a rule or a selector that is too wide"
    fi
}

# --- 1. Every file of ci/ -------------------------------------------------------

for values in "$chart"/ci/*.yaml; do
    name="ci/$(basename "$values")"
    echo "render: $name"

    if helm lint --strict "$chart" --values "$values" > "$work/lint.txt" 2>&1; then
        passed
    else
        fail "$name: helm lint --strict: $(tail -n 5 "$work/lint.txt" | tr '\n' ' ')"
    fi

    rendered="$work/$(basename "$values" .yaml).rendered.yaml"
    if ! render "$rendered" --values "$values"; then
        fail "$name: does not render: $(head -c 400 "$rendered.err" | tr '\n' ' ')"
        continue
    fi
    passed

    if validate "$rendered" > "$work/validate.txt" 2>&1; then
        passed
    else
        fail "$name: the manifests are not valid for Kubernetes $kubernetes_version: $(tail -n 5 "$work/validate.txt" | tr '\n' ' ')"
    fi

    rules "$name" "$rendered"
done

# The validator rejects a field that does not exist, and the rules reject a
# rule without peers: both are shown a manifest that was changed for it.
if [[ -f "$work/minimal.rendered.yaml" && -f "$work/full.rendered.yaml" ]]; then
    sed 's/^  type: ClusterIP$/  type: ClusterIP\n  noSuchField: 1/' "$work/minimal.rendered.yaml" > "$work/unknown-field.yaml"
    if validate "$work/unknown-field.yaml" > "$work/validate.txt" 2>&1; then
        fail "the validator accepts a field that does not exist"
    else
        passed
    fi

    # One client and nobody else, so that its rule has one peer.
    render "$work/one.yaml" --values "$minimal" --set-json 'clients=[{"podLabels":{"app":"api"}}]' \
        || fail "one client does not render"

    before="$failures"
    awk '
        /^        - namespaceSelector:$/ && !done { skip = 1; done = 1; next }
        skip && /^      ports:$/ { skip = 0 }
        skip { next }
        { print }
    ' "$work/one.yaml" > "$work/no-peer.yaml"
    rules "a rule without a peer" "$work/no-peer.yaml" 2> "$work/no-peer.txt"
    if [[ "$failures" -eq "$before" ]]; then
        fail "the rules accept a NetworkPolicy rule without a peer"
    else
        failures="$before"
        passed
    fi

    before="$failures"
    sed 's/^              "app": "api"$/              {}/' "$work/one.yaml" > "$work/empty-selector.yaml"
    rules "an empty selector" "$work/empty-selector.yaml" 2> "$work/empty-selector.txt"
    if [[ "$failures" -eq "$before" ]]; then
        fail "the rules accept an empty pod selector"
    else
        failures="$before"
        passed
    fi

    before="$failures"
    sed 's/^            defaultMode: 288$/            defaultMode: 420/' "$work/one.yaml" > "$work/open-mode.yaml"
    rules "a file mode for everybody" "$work/open-mode.yaml" 2> "$work/open-mode.txt"
    if [[ "$failures" -eq "$before" ]]; then
        fail "the rules accept a volume that everybody can read"
    else
        failures="$before"
        passed
    fi
fi

# --- 2. What depends on a value -------------------------------------------------

echo "render: what depends on a value"

# Nobody is listed: no ingress rule, and the name service is the only
# place the proxy may connect to.
if render "$work/nobody.yaml" --values "$minimal"; then
    document "$work/nobody.yaml" NetworkPolicy > "$work/policy.yaml"
    expect "no client: no ingress rule" "$work/policy.yaml" 0 'from:'
    expect "no client: ingress is the empty list" "$work/policy.yaml" 1 '^  ingress: \[\]$'
    expect "no database peer: one egress rule" "$work/policy.yaml" 1 '^    - to:$'
    expect "no database peer: it is the name service" "$work/policy.yaml" 1 '^              "k8s-app": "kube-dns"$'
    expect "no database peer: the name service port and no other" "$work/policy.yaml" 2 '^          port: 53$'
    expect "no database peer: no other port" "$work/policy.yaml" 2 '^          port: '
    expect "no scraper: no metrics port in the pod" "$work/nobody.yaml" 0 "name: metrics|$(number 9642)"
    expect "no scraper: the metrics stay on their default" "$work/nobody.yaml" 0 '^    metrics:'
    expect "default grace: 25 seconds for sessions" "$work/nobody.yaml" 1 '^      grace_period: 25s$'
    expect "default grace: 30 seconds for the pod" "$work/nobody.yaml" 1 '^      terminationGracePeriodSeconds: 30$'
    expect "default: no wait before the stop" "$work/nobody.yaml" 0 'preStop'
    expect "default: two replicas" "$work/nobody.yaml" 1 '^  replicas: 2$'
    expect "default: one pod may be taken away" "$work/nobody.yaml" 1 '^  maxUnavailable: 1$'
    expect "TLS off: no certificate is mounted" "$work/nobody.yaml" 0 'client-tls'
else
    fail "the minimal values do not render"
fi

# One client: one ingress rule, for the proxy port, from pods with that
# label in the namespace of the release.
if render "$work/client.yaml" --values "$minimal" \
    --set-json 'clients=[{"podLabels":{"app.kubernetes.io/name":"api"}}]' \
    --set-json 'database.peers=[{"cidr":"192.0.2.10/32"}]'; then
    document "$work/client.yaml" NetworkPolicy > "$work/policy.yaml"
    expect "one client: one ingress rule" "$work/policy.yaml" 1 '^    - from:$'
    expect "one client: its namespace is the one of the release" "$work/policy.yaml" 1 \
        "^              kubernetes.io/metadata.name: \"$namespace\"\$"
    expect "one client: its label" "$work/policy.yaml" 1 '^              "app.kubernetes.io/name": "api"$'
    expect "one client: the proxy port, and the database port" "$work/policy.yaml" 2 '^          port: 5432$'
    expect "one database peer: two egress rules" "$work/policy.yaml" 2 '^    - to:$'
    expect "one database peer: its address" "$work/policy.yaml" 1 '^            cidr: "192.0.2.10/32"$'
    expect "one client: still no metrics port" "$work/policy.yaml" 0 '9642'
else
    fail "one client does not render: $(head -c 400 "$work/client.yaml.err" | tr '\n' ' ')"
fi

# A scraper: the metrics leave loopback, on a port of the pod that the
# policy opens to the scraper and that the Service does not carry.
if render "$work/scraper.yaml" --values "$minimal" \
    --set-json 'metrics.scrapers=[{"namespace":"monitoring","podLabels":{"app":"prometheus"}}]'; then
    document "$work/scraper.yaml" NetworkPolicy > "$work/policy.yaml"
    document "$work/scraper.yaml" Service > "$work/service.yaml"
    expect "a scraper: one ingress rule" "$work/policy.yaml" 1 '^    - from:$'
    expect "a scraper: for the metrics port" "$work/policy.yaml" 1 '^          port: 9642$'
    expect "a scraper: not for the proxy port" "$work/policy.yaml" 0 '^          port: 5432$'
    expect "a scraper: its namespace" "$work/policy.yaml" 1 '^              kubernetes.io/metadata.name: "monitoring"$'
    expect "a scraper: the metrics listen on the pod" "$work/scraper.yaml" 1 '^      listen: 0.0.0.0:9642$'
    expect "a scraper: the pod names the port" "$work/scraper.yaml" 1 '^              containerPort: 9642$'
    expect "a scraper: the Service does not" "$work/service.yaml" 0 "name: metrics|$(number 9642)"
else
    fail "a scraper does not render: $(head -c 400 "$work/scraper.yaml.err" | tr '\n' ' ')"
fi

# No name service either: nothing may leave the pod.
if render "$work/sealed.yaml" --values "$minimal" --set-json 'dns.peers=[]'; then
    document "$work/sealed.yaml" NetworkPolicy > "$work/policy.yaml"
    expect "no peer at all: no egress rule" "$work/policy.yaml" 0 'to:'
    expect "no peer at all: egress is the empty list" "$work/policy.yaml" 1 '^  egress: \[\]$'
    expect "no peer at all: both directions are still covered" "$work/policy.yaml" 2 '^    - (Ingress|Egress)$'
else
    fail "an empty name service list does not render"
fi

# Every value set.
if [[ -f "$work/full.rendered.yaml" ]]; then
    full="$work/full.rendered.yaml"
    document "$full" NetworkPolicy > "$work/policy.yaml"
    document "$full" Deployment > "$work/deployment.yaml"
    expect "full: two ingress rules" "$work/policy.yaml" 2 '^    - from:$'
    expect "full: a webhook without peers gets no rule" "$work/policy.yaml" 4 '^    - to:$'
    expect "full: the database's own port" "$work/policy.yaml" 1 '^          port: 5433$'
    expect "full: a Secret for each webhook" "$work/deployment.yaml" 3 '^            secretName: ".*-webhook"$'
    expect "full: both token Secrets" "$work/deployment.yaml" 2 '^            secretName: "shop-tokens(-finance)?"$'
    expect "full: both token patterns" "$full" 2 '^    - /etc/pgsnare-secrets/tokens-[01]/\*\.yaml$'
    expect "full: the wait, the sessions and the margin" "$work/deployment.yaml" 1 '^      terminationGracePeriodSeconds: 50$'
    expect "full: the wait before the stop" "$work/deployment.yaml" 1 '^                seconds: 5$'
    expect "full: a label of the chart cannot be replaced" "$full" 0 'not-this'
    expect "full: the label that is allowed" "$work/deployment.yaml" 1 '^        "team": "security"$'
    expect "full: the authorities for webhooks" "$work/deployment.yaml" 1 '^              value: "/etc/pgsnare-secrets/webhook-ca/ca.crt"$'
    expect "full: the certificate of the listener" "$full" 1 '^        cert: /etc/pgsnare-secrets/client-tls/tls.crt$'
    expect "full: text that looks like a number stays text" "$full" 1 '^        sqlstate: "57014"$'
    expect "full: a large number stays a number" "$full" 1 '^        max_sessions: 1000000$'
fi

# --- 3. Refusals ------------------------------------------------------------------

echo "render: refusals"

# The values every refusal starts from render.
accepted "the minimal values" --values "$minimal"

# The values of the chart alone lack the three required ones.
refused "the defaults alone" 'schema.*digest' --set proxy.clientTLS.mode=disable
refused "TLS required and no certificate named" 'clientTLS.secretName is required' \
    --values "$minimal" --set proxy.clientTLS.mode=require

# An unknown value.
by_schema "an unknown value" "additional properties 'nope'" --set nope=1
by_schema "an unknown value in a group" "additional properties 'nope'" --set proxy.nope=1
by_schema "an unknown setting of the configuration" "additional properties 'rules'" --set config.rules.on_parse_failure=allow
by_schema "an address for the admin listener" "additional properties 'admin'" --set admin.listen=0.0.0.0:9641
by_schema "an address for the admin listener, in the configuration" "additional properties 'admin'" --set config.admin.listen=0.0.0.0:9641
by_schema "an address for the metrics listener" "additional properties 'listen'" --set metrics.listen=0.0.0.0:9642
by_schema "another kind of Service" "additional properties 'service'" --set service.type=LoadBalancer
by_schema "a switch for the NetworkPolicy" "additional properties 'networkPolicy'" --set networkPolicy.enabled=false
by_schema "a security context from the values" "additional properties 'securityContext'" --set securityContext.privileged=true
by_schema "a webhook over plain HTTP" "additional properties 'allow_insecure_http'" \
    --set-json 'sinks.webhooks=[{"secretName":"hook","config":{"allow_insecure_http":true}}]'

# A missing digest, and anything else that is not a digest.
by_schema "an empty digest" "/image/digest" --set image.digest=
by_schema "a digest of another form" "/image/digest" --set image.digest=sha256:abc
by_schema "a tag in place of the digest" "additional properties 'tag'" --set image.tag=1.0.0
by_schema "a tag in the repository" "/image/repository" --set image.repository=registry.example.com/pgsnare:latest
by_schema "a digest in the repository" "/image/repository" \
    --set image.repository=registry.example.com/pgsnare@sha256:0000000000000000000000000000000000000000000000000000000000000000
by_templates "an empty digest" "image.digest is required" --set image.digest=
by_templates "a tag in the repository" "image.repository must be" --set image.repository=registry.example.com/pgsnare:latest

# A token value, or another secret, in the values.
accepted "a token Secret by name" --values "$minimal" --set-json 'tokens={"secretNames":["one","two"]}'
by_schema "a token value next to the Secret names" "additional properties 'values'" \
    --set-json 'tokens={"secretNames":["one"],"values":["svc.backup.8f3k2q@mail.example"]}'
by_schema "tokens as the configuration file writes them" "/tokens" \
    --set-json 'tokens=[{"id":"users-admin-backup","values":["svc.backup.8f3k2q@mail.example"]}]'
by_schema "tokens among the copied settings" "additional properties 'tokens'" \
    --set-json 'config.tokens=[{"id":"users-admin-backup","values":["svc.backup.8f3k2q@mail.example"]}]'
by_schema "no token Secret" "/tokens/secretNames" --set-json 'tokens={"secretNames":[]}'
by_templates "no token Secret" "tokens.secretNames is required" --set-json 'tokens={"secretNames":[]}'
accepted "a webhook by its Secret" --values "$minimal" --set-json 'sinks.webhooks=[{"secretName":"hook"}]'
by_schema "the address of a webhook" "additional properties 'url'" \
    --set-json 'sinks.webhooks=[{"secretName":"hook","url":"https://alerts.example.com/hook"}]'
by_schema "the signing key of a webhook" "additional properties 'hmac_secret'" \
    --set-json 'sinks.webhooks=[{"secretName":"hook","hmac_secret":"0000000000000000000000000000000000000000000000000000000000000000"}]'
by_schema "a private key" "additional properties 'key'" --set proxy.clientTLS.key=text

# A list item that would mean everybody.
accepted "a client with a label" --values "$minimal" --set-json 'clients=[{"podLabels":{"app":"api"}}]'
by_schema "a client without labels" "minProperties" --set-json 'clients=[{"podLabels":{}}]'
by_schema "a client that is only a namespace" "podLabels" --set-json 'clients=[{"namespace":"shop"}]'
by_schema "an empty client" "podLabels" --set-json 'clients=[{}]'
by_schema "a client by address" "additional properties 'cidr'" --set-json 'clients=[{"cidr":"192.0.2.0/24"}]'
by_schema "a namespace by selector" "additional properties 'namespaceSelector'" \
    --set-json 'clients=[{"namespaceSelector":{},"podLabels":{"app":"api"}}]'
by_schema "a scraper without labels" "minProperties" --set-json 'metrics.scrapers=[{"podLabels":{}}]'
by_templates "a client without labels" "clients\[0\]: podLabels needs at least one label" --set-json 'clients=[{"podLabels":{}}]'
by_templates "an empty client" "clients\[0\]: podLabels needs at least one label" --set-json 'clients=[{}]'
by_templates "a client that is only a namespace" "clients\[0\]: podLabels needs at least one label" --set-json 'clients=[{"namespace":"shop"}]'
by_templates "a client by address" "clients\[0\]: only pods can be named here" --set-json 'clients=[{"cidr":"192.0.2.0/24"}]'
by_templates "a scraper without labels" "metrics.scrapers\[0\]: podLabels needs" --set-json 'metrics.scrapers=[{"podLabels":{}}]'
accepted "a database by address" --values "$minimal" --set-json 'database.peers=[{"cidr":"192.0.2.10/32"}]'
by_schema "every address as the database" "/database/peers/0" --set-json 'database.peers=[{"cidr":"0.0.0.0/0"}]'
by_schema "every IPv6 address as the database" "/database/peers/0" --set-json 'database.peers=[{"cidr":"::/0"}]'
by_schema "a peer that is pods and addresses" "/database/peers/0" \
    --set-json 'database.peers=[{"cidr":"192.0.2.10/32","podLabels":{"app":"db"}}]'
by_schema "a database peer without labels" "/database/peers/0" --set-json 'database.peers=[{"namespace":"data","podLabels":{}}]'
by_templates "every address as the database" "database.peers\[0\]: cidr must be" --set-json 'database.peers=[{"cidr":"0.0.0.0/0"}]'
by_templates "every IPv6 address as the database" "database.peers\[0\]: cidr must be" --set-json 'database.peers=[{"cidr":"::/0"}]'
by_templates "a database peer without labels" "database.peers\[0\]: podLabels needs" --set-json 'database.peers=[{"namespace":"data","podLabels":{}}]'
by_templates "every address as the name service" "dns.peers\[0\]: cidr must be" --set-json 'dns.peers=[{"cidr":"0.0.0.0/0"}]'
by_templates "every address as a webhook receiver" "sinks.webhooks\[0\].peers\[0\]: cidr must be" \
    --set-json 'sinks.webhooks=[{"secretName":"hook","peers":[{"cidr":"0.0.0.0/0"}]}]'

# Values that contradict each other or the pod.
by_schema "no replica" "/replicaCount" --set replicaCount=0
by_schema "a port only root can open" "/proxy/port" --set proxy.port=443
refused "the proxy on the admin port" "proxy.port must not be" --values "$minimal" --set proxy.port=9641
refused "no sink" "at least one sink is required" --values "$minimal" --set sinks.stdout=false
refused "a certificate authority without verification" "caSecretName is only used with mode verify-full" \
    --values "$minimal" --set database.tls.mode=require --set database.tls.caSecretName=db-ca
by_templates "no database" "database.host is required" --set database.host=

# --- 4. The configuration files, by the binary ------------------------------------

check_configuration() {
    local name="$1" rendered="$2" directory="$3" file index
    mkdir -p "$directory/secrets"
    # The file as the pod would see it, with the mounted Secrets in a
    # directory of this test.
    document "$rendered" ConfigMap \
        | awk '/^  pgsnare\.yaml: \|$/ { inside = 1; next } inside && /^    / { print substr($0, 5); next } inside { inside = 0 }' \
        | sed "s#/etc/pgsnare-secrets#$directory/secrets#g" > "$directory/pgsnare.yaml"
    [[ -s "$directory/pgsnare.yaml" ]] || { fail "$name: no configuration file in the ConfigMap"; return; }

    # What the Secrets would hold. Everything is made here and is worth
    # nothing: a token value, a certificate for a documentation name, an
    # address in a documentation domain and a random key.
    while IFS= read -r file; do
        mkdir -p "$(dirname "$file")"
        case "$file" in
            */tokens-*/\*.yaml)
                index="$(basename "$(dirname "$file")")"
                printf 'tokens:\n  - id: render-%s\n    values: ["render-%s-%s"]\n' \
                    "$index" "$index" "$(openssl rand -hex 12)" > "$(dirname "$file")/seeded.yaml"
                ;;
            */tls.crt | */ca.crt)
                cp "$work/certificate.pem" "$file"
                ;;
            */tls.key)
                cp "$work/key.pem" "$file"
                ;;
            */url)
                printf 'https://alerts.example.com/hooks/pgsnare\n' > "$file"
                ;;
            */hmac-secret)
                openssl rand -hex 32 > "$file"
                ;;
            *)
                fail "$name: the configuration names a file this test does not know: ${file#"$directory/"}"
                ;;
        esac
    done < <(grep -o -E "$directory/secrets/[^[:space:]\"']+" "$directory/pgsnare.yaml" | sort -u)
    find "$directory" -type f -exec chmod 0600 {} +

    if "$binary" config check --config "$directory/pgsnare.yaml" > "$directory/check.txt" 2>&1; then
        passed
    else
        fail "$name: pgsnare config check refuses the configuration of the chart: $(sed "s#$directory#.#g" "$directory/check.txt" | tail -n 8 | tr '\n' ' ')"
        return
    fi

    # The check can fail: the same file with a setting that does not exist.
    printf 'no_such_setting: true\n' >> "$directory/pgsnare.yaml"
    if "$binary" config check --config "$directory/pgsnare.yaml" > "$directory/check.txt" 2>&1; then
        fail "$name: pgsnare config check accepts a setting that does not exist"
    else
        passed
    fi
}

if [[ -n "$binary" ]]; then
    echo "render: the configuration files, checked by $("$binary" --version 2>/dev/null || echo pgsnare)"
    command -v openssl >/dev/null || { echo "render: openssl is not on the path" >&2; exit 1; }
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$work/key.pem" -out "$work/certificate.pem" -days 1 \
        -subj "/CN=db.example.com" -addext "subjectAltName=DNS:db.example.com" 2> /dev/null
    for values in "$chart"/ci/*.yaml; do
        name="ci/$(basename "$values")"
        rendered="$work/$(basename "$values" .yaml).rendered.yaml"
        [[ -f "$rendered" ]] || continue
        check_configuration "$name" "$rendered" "$work/check-$(basename "$values" .yaml)"
    done
else
    echo "render: no binary given, so the configuration files are not checked by pgsnare"
fi

# --- Result -----------------------------------------------------------------------

if [[ "$failures" -ne 0 ]]; then
    echo "render: $failures of $((checks + failures)) checks failed" >&2
    exit 1
fi
echo "render: all $checks checks passed"
