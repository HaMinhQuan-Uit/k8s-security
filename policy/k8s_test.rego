package main

# ============================================
# TEST 1: Privileged container phải bị deny
# ============================================
# Giả lập input: pod có privileged: true
# Mong đợi: deny trả về message chứa "Privileged"
test_deny_privileged {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "securityContext": {"privileged": true}
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 2: Non-privileged container phải pass
# ============================================
# Giả lập input: pod có privileged: false
# Mong đợi: deny về privileged trống (không vi phạm)
test_allow_non_privileged {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "good",
                "image": "busybox:1.36",
                "securityContext": {
                    "privileged": false,
                    "runAsNonRoot": true,
                    "runAsUser": 1000
                },
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) == 0
}

# ============================================
# TEST 3: HostPath volume phải bị deny
# ============================================
# Giả lập: pod mount hostPath /etc
# Mong đợi: deny trả về message chứa "HostPath"
test_deny_hostpath {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "securityContext": {"runAsNonRoot": true},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }],
            "volumes": [{
                "name": "host-vol",
                "hostPath": {"path": "/etc"}
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 4: HostNetwork phải bị deny
# ============================================
test_deny_hostnetwork {
    result := deny with input as {
        "spec": {
            "hostNetwork": true,
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "securityContext": {"runAsNonRoot": true},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 5: HostPID phải bị deny
# ============================================
test_deny_hostpid {
    result := deny with input as {
        "spec": {
            "hostPID": true,
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "securityContext": {"runAsNonRoot": true},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 6: :latest tag phải bị deny
# ============================================
test_deny_latest_tag {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "nginx:latest",
                "securityContext": {"runAsNonRoot": true},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 7: Image không có tag phải bị deny
# ============================================
test_deny_no_tag {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "nginx",
                "securityContext": {"runAsNonRoot": true},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 8: Thiếu CPU request phải bị deny
# ============================================
test_deny_missing_cpu_request {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "securityContext": {"runAsNonRoot": true}
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 9: Thiếu runAsNonRoot phải bị deny
# ============================================
test_deny_missing_nonroot {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "bad",
                "image": "busybox:1.36",
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) > 0
}

# ============================================
# TEST 10: Pod hoàn toàn hợp lệ phải pass (0 violations)
# ============================================
test_allow_safe_pod {
    result := deny with input as {
        "spec": {
            "containers": [{
                "name": "good",
                "image": "busybox:1.36",
                "securityContext": {
                    "privileged": false,
                    "runAsNonRoot": true,
                    "runAsUser": 1000
                },
                "resources": {
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "200m", "memory": "128Mi"}
                }
            }]
        }
    }
    count(result) == 0
}
