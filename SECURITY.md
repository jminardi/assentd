# Security

assentd is a personal project and has not had a professional security audit. Read the threat
model in the README for what it does and doesn't protect against.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository.
Don't open a public issue for anything that could put someone's secrets at risk.

Useful to include: what an attacker needs (code running as the user? a tailnet device? root?),
what they get, and steps or a proof of concept against a throwaway vault (`tests/test_e2e.py`
shows how to start one).

This is maintained in spare time: expect an acknowledgement within a week, not a day.
