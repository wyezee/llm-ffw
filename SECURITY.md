# Security policy

## Reporting a vulnerability

Use the repository's private GitHub vulnerability-reporting form. If that form
is unavailable, contact the deployment owner's approved private security
channel. Do not open a public issue for an unpatched vulnerability.

Never include live credentials, raw prompts, model output, customer data, or a
full matching value. Use deterministic synthetic data and describe the affected
rule, catalog version, policy, Python version, and smallest safe reproduction.

The repository owner must enable GitHub private vulnerability reporting before
an external release. Receipt, severity triage, coordinated disclosure, and
revocation of any accidentally exposed credential remain owner responsibilities.

## Supported versions

Until the first tagged stable release, security fixes are applied only to the
latest `0.1.x` pre-release line. Older snapshots and untagged forks are not
supported.

## Security boundary

LLM FFW is a deterministic inspection and policy library. It is not a process
sandbox, data-loss-prevention system, credential validator, or complete secret
inventory. Detection can have false negatives when providers introduce new
formats and false positives where a constrained format is not uniquely secret.

The host application remains responsible for authentication, authorization,
transport security, request-size enforcement, log redaction, process isolation,
catalog rollout, incident response, and credential revocation.
