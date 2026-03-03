# Mobile Security Policy

This folder contains mobile security policy, checklists, and release gates for iOS and Android.

Minimum requirements:

- Follow OWASP MASVS and platform-specific guidance (ATS, Network Security Config, secure storage).
- Enforce TLS 1.3 where supported, certificate pinning for sensitive APIs, and strict deep link allowlists.
- Block release if debuggable flags, cleartext traffic, or insecure storage are detected.
