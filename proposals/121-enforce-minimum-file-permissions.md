# 121 - Enforce minimum access rights on confidential files

Kroxylicious should validate that confidential files (TLS private keys, keystores, truststores,
password files, and KMS credential files) have suitably restrictive filesystem permissions before
reading them, similar to how the `ssh` command refuses to use a world-readable private key.

## Current situation

Kroxylicious reads confidential material from the filesystem - TLS private keys, keystores,
truststores, and passwords - without checking whether those files are accessible by users other
than the owner. A world-readable private key file (`0644`) is silently accepted and used. This
violates the principle of least privilege and increases the risk of credential exposure through
over-permissive filesystem configurations.

## Motivation

Security best practices require that private key material is accessible only to the process that
owns it. Tools such as `ssh`, `gpg`, and many TLS libraries enforce this by refusing to operate
on files with group or other read bits set. Kroxylicious should provide equivalent protection.

The threat model includes:
- Accidental over-permissive file creation (e.g. default `umask` producing `0644`).
- Multi-tenant environments where other users on the same host could read Kroxylicious credentials.
- Kubernetes deployments where secret volumes default to world-readable `0644` unless explicitly
  configured otherwise.

## Proposal

### File permission policy

Introduce a configurable `security.filePermissions.policy` setting with three modes:

- `STRICT` - files must be owner-only (equivalent to `chmod 400` or `chmod 600`). Any group or
  other read/write/execute bits cause an `IllegalStateException` at startup. Mirrors SSH behaviour.
- `RELAXED` - other-user bits are forbidden, but group bits are permitted. This supports
  Kubernetes deployments where `fsGroup` is used to grant a specific GID read access to mounted
  secrets (e.g. `defaultMode: 0440`).
- `DISABLED` - no enforcement. A warning is logged for files that would be rejected by other
  policies, but startup is never rejected. This is the default for backward compatibility; see
  the [Delivery](#delivery) section for how the default will eventually change to `STRICT`.

### Scope of enforcement

The policy applies before reading any of the following:

- TLS private key files (`key.privateKeyFile`)
- TLS keystore and truststore files (`key.storeFile`, `trust.storeFile`)
- Password files referenced by `FilePassword` providers (including KMS credentials)
- AWS IRSA web identity token files
- AWS EKS Pod Identity authorization token files

### Configuration

```yaml
---
management:
  # ...
virtualClusters:
    - name: "one"
      targetCluster:
        # ...
      gateways:
        # ...
security:
    filePermissions:
        policy: "STRICT"
```

### Global policy propagation

`FilePermissionValidator` holds a static `AtomicReference<Policy>` that is set once when
`Configuration` is constructed. This allows `FilePassword` and KMS credential providers - which
live in modules that do not depend on `kroxylicious-runtime` - to enforce the configured policy
without requiring changes to their public interfaces.

### Kubernetes operator

The operator mounts all secret volumes with `defaultMode: 0440` (group-readable, no world
access).

On plain Kubernetes, it sets `fsGroup` and `runAsGroup` to the
[Kroxylicious Dockerfile](kroxylicious-app/src/main/docker/proxy.dockerfile) GID (185)
so the kubelet chowns volume files to that GID and the container process can read them via group
membership.

On OpenShift,
[`fsGroup` and `runAsGroup` are omitted](https://www.redhat.com/en/blog/a-guide-to-openshift-and-uids);
[the `restricted-v2` SCC's `MustRunAs` strategy injects the namespace-allocated GID automatically](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/authentication_and_authorization/managing-pod-security-policies#security-context-constraints-example_configuring-internal-oauth).

The `KafkaProxy` CRD exposes `spec.security.filePermissions.policy` (default `RELAXED`) to allow
users to override the policy.

## Affected/not affected projects

**Affected:**
- `kroxylicious-security` - new module; contains `FilePermissionValidator` and `FilePermissionConfig`
- `kroxylicious-api` - `FilePassword.getProvidedPassword()` now validates permissions
- `kroxylicious-runtime` - `Configuration`, `NettyKeyProvider`, `NettyTrustProvider`, `VirtualClusterModel`, `ServerConnectionStateMachine`
- `kroxylicious-kms-providers` / `kroxylicious-kms-provider-aws-kms` - IRSA and Pod Identity providers validate their token files
- `kroxylicious-kubernetes` / `kroxylicious-operator` - secret volume `defaultMode`, conditional `fsGroup`, `KafkaProxy` CRD field

**Not affected:**
- `kroxylicious-filters` - no file reading
- `kroxylicious-authorizer-api`, `kroxylicious-authorizer-providers` - no file reading
- KMS providers other than AWS (vault token, Azure, Fortanix) - covered transitively via `FilePassword`

## Delivery

In order to comply with the project's [deprecation policy](https://github.com/kroxylicious/kroxylicious/blob/main/DEV_GUIDE.md#deprecation-policy),
the change in default policy should be staged across two releases.

**Stage 1 (this proposal):** Introduce the feature with `DISABLED` as the default for backward
compatibility. When `DISABLED` is the effective policy, Kroxylicious logs a `WARN` for every
confidential file whose permissions would be rejected by `STRICT`. This gives users a
deprecation period to identify and harden their file permissions. The deprecation of `DISABLED`
as the default should be announced in the `CHANGELOG` under "Changes, deprecations and removals".

**Stage 2 (subsequent release, following the deprecation policy):** Change the default to `STRICT`.
This will be a breaking change for deployments that have confidential files with overly permissive
permissions and have not explicitly configured a policy. Deployments that set
`security.filePermissions.policy: DISABLED` explicitly will be unaffected.
The change in default should be documented in the `CHANGELOG` as a breaking change.

## Compatibility

### Backward compatibility

The default policy in Stage 1 is `DISABLED`, so existing deployments are unaffected. Warnings are
emitted for insecure files to assist users in identifying files to harden before the default
changes to `STRICT` in Stage 2.

### `FilePassword.getProvidedPassword()` behaviour change

With a non-`DISABLED` policy, `FilePassword.getProvidedPassword()` can now throw
`IllegalStateException` if the password file has group or other read bits set. This is an
unchecked exception that did not previously occur. Filter authors using `FilePassword` directly
should be aware of this.

### API additions

`FilePermissionValidator` and `FilePermissionConfig` in the new `kroxylicious-security` module
become accessible to consumers of `kroxylicious-api` (which depends on `kroxylicious-security`).
`FilePermissionValidator.setGlobalPolicy()` is necessarily public because `Configuration` (in
`kroxylicious-runtime`) and `FilePermissionValidator` (in `kroxylicious-security`) are in
different modules and Java's access control cannot express "accessible to exactly one other module"
without JPMS. This is a known design limitation: third-party code could in principle call
`setGlobalPolicy()` and alter the global policy for all validations. A future improvement could
adopt JPMS module encapsulation to restrict the method to the `kroxylicious.runtime` module only.

## Rejected alternatives

### Move `FilePermissionValidator` to `kroxylicious-runtime`

`FilePassword` (in `kroxylicious-api`) needs to call the validator to enforce permissions before
reading a password file. `kroxylicious-runtime` already depends on `kroxylicious-api`, so
`kroxylicious-api` depending back on `kroxylicious-runtime` would create a circular dependency.
The validator therefore cannot live in `kroxylicious-runtime` if `FilePassword` is to use it
directly.

### Move `FilePermissionValidator` to `kroxylicious-api`

Moving the validator directly to `kroxylicious-api` (rather than creating `kroxylicious-security`)
was considered. Rejected because `kroxylicious-api` is conceptually a contract/interface layer;
adding a logging-heavy implementation utility (with SLF4J, `AtomicBoolean`, `ConcurrentHashMap`)
would pollute the API module with infrastructure concerns. A dedicated `kroxylicious-security`
module is the right architectural home.

### System property override

A JVM system property (`-Dkroxylicious.security.filePermissionPolicy=STRICT`) was considered as
a secondary configuration mechanism alongside the YAML field. Rejected because system properties
are undiscoverable, untestable, and bypass the normal configuration validation path. The YAML
field is the right single mechanism.