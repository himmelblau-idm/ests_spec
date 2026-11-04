# Unofficial eSTS Protocol Specification

This repository is the home of the unofficial Microsoft Entra ID Security
Token Service (eSTS) interactive multi-factor authentication specification.
It documents the HTTP APIs and flow state used to authenticate users and
obtain OAuth 2.0 authorization codes without rendering the eSTS sign-in pages
in a browser UI.

The Himmelblau project maintains this specification for other implementors.
It covers authentication discovery, passwordless and password-based sign-in,
MFA challenges, post-authentication interrupts, and token exchange, as well
as the OAuth 2.0 device authorization grant.

The source document is [ests-spec.md](ests-spec.md). Generated HTML and
PDF versions are produced from that file for easier reading and distribution.

## Build Instructions

The build requires:

- `pandoc`
- Google Chrome available as `google-chrome`

Run:

```sh
make
```

The build creates `ests-spec.html` with `pandoc`, then renders
`ests-spec.pdf` from the HTML using headless Google Chrome.

To remove generated artifacts, run:

```sh
make clean
```
