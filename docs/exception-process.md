# Exception Process — Quy trình xử lý Exception cho K8s Policy

## Khi nào cần exception?

- Workload hệ thống cần privileged (monitoring, logging agents)
- Namespace cần hostPath cho storage
- Tool cần capabilities đặc biệt (network tools cần NET_ADMIN)

## Cách request exception

1. Developer tạo GitHub Issue với label `policy-exception`
2. Ghi rõ: namespace, workload, policy bị vi phạm, lý do cần exception
3. Security team review trong 24 giờ
4. Nếu approve → thêm namespace vào excludedNamespaces trong Constraint

## Cách thêm exception

Sửa file constraint, ví dụ cho namespace `monitoring`:

```yaml
spec:
  match:
    excludedNamespaces:
      - kube-system
      - gatekeeper-system
      - monitoring        # Exception approved, ticket #XX
```

## TTL & Review

- Mỗi exception có TTL tối đa 90 ngày
- Review lại khi hết hạn
- Nếu không renew → tự động remove exception

## Bài học thực tế từ project

Prometheus và Grafana bị Gatekeeper chặn vì thiếu resource limits.
Giải pháp: thêm `monitoring` vào excludedNamespaces.
Đây là tình huống thường gặp trong doanh nghiệp — policy strict
chặn luôn infrastructure tools.
