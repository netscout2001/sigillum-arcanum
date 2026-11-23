# Security Policy

## Supported versions

Only the latest release on the default branch receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's
[private vulnerability reporting](../../security/advisories/new) ("Report a vulnerability" on the Security tab).
Do not open a public issue.

Helpful in a report:

* affected version and component (e.g. `sigillum/ratchet.py`, file format, GUI),
* a description of the attack and its preconditions (which factors or files the attacker holds),
* a proof of concept or test case if possible.

This is a spare-time project. You can expect an acknowledgement within 14 days. Fixes are released as soon as
practical; reporters are credited unless they prefer otherwise.

## Scope

In scope: cryptographic design and implementation, file and message formats, key handling, the hand cipher,
the GUI's handling of secrets.

Out of scope: attacks that require malware on the user's running computer, physical coercion, or all factors
(identity file, key file, passphrase, PIN, YubiKey) at once – these are documented limitations.
