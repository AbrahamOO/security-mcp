# Mobile Release Gates

Release is blocked unless:

- iOS ATS is strict (no NSAllowsArbitraryLoads exceptions without approval).
- Android cleartext traffic is disabled and Network Security Config is strict.
- Debuggable flags are disabled for release builds.
- Certificate pinning is enabled for sensitive API domains.
- Secrets are stored only in platform secure storage.
