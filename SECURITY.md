# Security policy

SecondFactor handles authentication-sensitive data. **Do not publish vulnerability details, exploit payloads, recovery codes, signing keys or sensitive logs in public issues.**

## Private vulnerability reports

Use [GitHub private vulnerability reporting](https://github.com/bwirehq/secondfactor/security/advisories/new) if enabled. If that feature is unavailable, contact the project owner privately using the contact options on the [bwirehq profile](https://github.com/bwirehq). Include the affected version, a concise impact summary, safe steps to reproduce using disposable credentials and a suggested mitigation.

Do not share production secrets or publicly disclose the vulnerability before coordinating with the maintainers.

## Supported versions

The latest released `0.1.x` patch is the intended recipient of security fixes; earlier versions may not receive backports. Published tags must never be moved to silently change the source.

## Scope

Identity assertions, callback replay, session binding, tenant isolation, privileged event access, recovery authorization, factor management, encryption and keys, SDK protocol mismatches, dependencies and supply-chain compromise are in scope.

Automated tests do not imply audit certification or guaranteed security. Reports will be triaged privately when maintainers are available; no formal SLA is promised.
