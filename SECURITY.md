# Security policy

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting for this repository, if enabled. Otherwise contact the repository owner privately through their GitHub profile; do not put secrets or exploit details in a public issue.

Only the latest published 0.1.x patch is intended to receive security fixes. Before the first release, all revisions are development candidates.

The security boundary includes tenant isolation, authenticated identity/session integration, factor lifecycle, recovery, cryptography, replay protection, SDK protocol behavior, and release artifacts. Examples' mock primary authentication is for local learning and must not be used as production identity infrastructure.

Never claim the project is audited or certified solely because automated checks pass. Review evidence must identify the reviewed revision, scope, findings, and limitations. No response-time or certification guarantees are made.
