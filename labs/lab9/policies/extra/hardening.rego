# Extra org checks, merged into the shipped k8s.security package so conftest
# evaluates them alongside the built-in rules.
package k8s.security

# DENY: images must be pinned by digest (@sha256:...), never by a mutable tag.
# A tag can be repointed at a different image after review (see Lab 8); a digest
# cannot. The shipped policy only blocks ":latest", not tags in general.
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  indexof(c.image, "@sha256:") == -1
  msg := sprintf("container %q image must be pinned by digest (@sha256:), not a tag", [c.name])
}

# WARN: every container should declare at least one containerPort, so Services
# and NetworkPolicies can target it explicitly instead of guessing.
warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.ports
  msg := sprintf("container %q should declare a containerPort", [c.name])
}
