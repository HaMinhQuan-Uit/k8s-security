# K8s Security Gate — OPA Gatekeeper Policy Enforcement

Security gate cho Kubernetes deployment sử dụng OPA Gatekeeper
để chặn manifest không an toàn trước khi deploy lên cluster.

## Architecture

## Policies (6 rules)

| Policy | Threat | Description |
|--------|--------|-------------|
| no-privileged | T1 - Pod escape | Block containers với privileged: true |
| no-hostpath | T2 - Data leakage | Block hostPath volume mounts |
| no-hostnetwork | T3 - Lateral movement | Block hostNetwork/hostPID/hostIPC |
| require-resources | T4 - DoS | Require CPU/memory requests + limits |
| no-latest-tag | T5 - Supply chain | Block :latest image tag |
| require-nonroot | T1 - Privilege escalation | Require runAsNonRoot: true |

## Quick Start

### Prerequisites
- Docker
- kubectl
- kind
- Helm

### Setup cluster + policies

```bash
# Create cluster
kind create cluster --name security-gate

# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.1/deploy/gatekeeper.yaml
kubectl wait --for=condition=Ready pods --all -n gatekeeper-system --timeout=120s

# Apply policies
kubectl apply -f policies/templates/
sleep 10
kubectl apply -f policies/constraints/
```

### Test

```bash
# Bad pod — should be DENIED
kubectl apply -f manifests/bad/privileged-pod.yaml
# Error: Privileged container not allowed

# Good pod — should be ACCEPTED
kubectl apply -f manifests/good/safe-pod.yaml
# pod/good-pod created
```

### CI (conftest)

```bash
conftest test manifests/bad/ --policy policy/
# 14 failures

conftest test manifests/good/ --policy policy/
# 12 passed, 0 failures
```

## Monitoring

Prometheus + Grafana dashboard tracking:
- `gatekeeper_constraint_templates` — active policies count
- Policy evaluation metrics

## Project Structure

## Test Results

| Test | Manifest | Expected | Result |
|------|----------|----------|--------|
| TC1 | privileged-pod.yaml | Denied (7 violations) | ❌ Denied |
| TC2 | hostpath-pod.yaml | Denied (6 violations) | ❌ Denied |
| TC3 | latest-tag-pod.yaml | Denied (1 violation) | ❌ Denied |
| TC4 | safe-pod.yaml | Accepted | ✅ Created |

## Lessons Learned

- Gatekeeper chặn luôn Prometheus/Grafana vì thiếu resource limits
  → Giải pháp: exclude namespace `monitoring`
- Policy cần test kỹ trước khi apply — có thể block infrastructure tools
- Conftest trong CI cho feedback sớm hơn Gatekeeper (shift-left)

## Author

Ha Minh Quan — UIT-VNUHCM
Information Security — 4th Year
