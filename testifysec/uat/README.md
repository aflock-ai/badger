# Local phase acceptance

Every phase has stable story/assertion IDs, real execution, retained machine-readable results and an explicit boundary. Synthetic cryptographic fixtures exercise real verification; they are not platform-issued credentials. Component success is not end-to-end ALPS qualification.

Run from the repository root, placing reports outside source. HC-00 verifies every imported byte, executable mode and symlink against the pinned upstream Git tree without needing a second checkout or network:

```sh
python3 testifysec/uat/import.py /tmp/hardened-opencode-uat/import.json
```

Run HC-00 on the import phase before upstream modifications. Later phases intentionally change that tree and use their own acceptance harness; the original report identifies the import baseline. Do not update the upstream pin merely to make a downstream change pass this check.

The monorepo onboarding harness at `.uat/onboarding-steel-thread/` remains the reusable platform/Pushgate integration harness. Native component phases do not need to provision a platform. Full delivery acceptance later requires its independently checked upstream commit and receipt, not just a passing client response.

Reports record measured results. Keep credentials and private keys out of report exports. Each stacked PR states its command, exact tested revision/artifact digests, assertions, limitations and parent PR.
