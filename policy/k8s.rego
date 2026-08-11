package main

# Deny privileged containers
deny[msg] {
  container := input.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Privileged container not allowed: %s", [container.name])
}

# Deny hostPath volumes
deny[msg] {
  volume := input.spec.volumes[_]
  volume.hostPath
  msg := sprintf("HostPath volume not allowed: %s (path: %s)", [volume.name, volume.hostPath.path])
}

# Deny hostNetwork
deny[msg] {
  input.spec.hostNetwork == true
  msg := "hostNetwork is not allowed"
}

# Deny hostPID
deny[msg] {
  input.spec.hostPID == true
  msg := "hostPID is not allowed"
}

# Deny hostIPC
deny[msg] {
  input.spec.hostIPC == true
  msg := "hostIPC is not allowed"
}

# Deny :latest tag
deny[msg] {
  container := input.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %s uses :latest tag", [container.name])
}

# Deny no tag
deny[msg] {
  container := input.spec.containers[_]
  not contains(container.image, ":")
  msg := sprintf("Container %s has no image tag", [container.name])
}

# Require runAsNonRoot
deny[msg] {
  container := input.spec.containers[_]
  not input.spec.securityContext.runAsNonRoot
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container %s must set runAsNonRoot: true", [container.name])
}

# Require resource requests
deny[msg] {
  container := input.spec.containers[_]
  not container.resources.requests.cpu
  msg := sprintf("Container %s must set CPU request", [container.name])
}

deny[msg] {
  container := input.spec.containers[_]
  not container.resources.requests.memory
  msg := sprintf("Container %s must set memory request", [container.name])
}

# Require resource limits
deny[msg] {
  container := input.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container %s must set CPU limit", [container.name])
}

deny[msg] {
  container := input.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container %s must set memory limit", [container.name])
}
