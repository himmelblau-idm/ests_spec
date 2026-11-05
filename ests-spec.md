<style>
body {
  font-family: Segoe UI,SegoeUI,Helvetica Neue,Helvetica,Arial,sans-serif;
  padding: 1em;
  margin: auto;
  max-width: 64em;
  background: #fefefe;
}
.protocol-table p {
  margin-top: 0px;
}
p {
  margin-top: 1rem;
  margin-bottom: 0px;
}
table {
  margin-top: 1rem;
  border: 1px solid #EAEAEA;
  border-collapse: collapse;
  width: 100%;
}
table, th, td {
  border-radius: 3px;
  padding: 5px;
}
th, td {
  font-size: .875rem;
  padding-top: 0.5rem;
  padding-bottom: 0.5rem;
  border: 1px solid #bbb;
  color: #2a2a2a;
}
th {
  background-color: #ededed;
  font-weight: 600;
}
td {
  padding: 0.5rem;
  background-color: #fff;
}
h1, h2, h3, h4, h5, h6 {
  font-weight: bold;
  color: #000;
}
h1 {
  font-size: 28px;
}
h2 {
  font-size: 24px;
}
h3 {
  font-size: 18px;
}
h4 {
  font-size: 16px;
}
h5 {
  font-size: 14px;
}
code, pre {
  font-family: Consolas, Monaco, monospace;
  font-size: .875rem;
}
pre {
  overflow-x: auto;
  background: #f6f8fa;
  padding: 0.75rem;
  border: 1px solid #eaeaea;
}
@media print {
  pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    overflow: visible;
  }
  .protocol-table {
    overflow-wrap: anywhere;
  }
}
</style>

# eSTS Interactive Multi-Factor Authentication Protocol

This document specifies the HTTP APIs used by the Microsoft Entra ID Security
Token Service (eSTS, written as ESTS below) to perform
interactive multi-factor authentication (MFA) and return an OAuth 2.0
authorization code, without requiring a browser UI to render the ESTS
sign-in pages.

This document describes wire behavior only: request URLs, headers, bodies,
response bodies, and the processing rules needed to consume them. Tokens,
canaries, cookies, and flow state values are opaque to the client unless
otherwise noted.

## Published Version

<table class="protocol-table"><thead>
  <tr>
   <th><p>Date</p></th>
   <th><p>Protocol Revision</p></th>
   <th><p>Revision Class</p></th>
  </tr>
 </thead><tbody>
 <tr>
  <td><p>11/04/2026</p></td>
  <td><p>0.01</p></td>
  <td><p>New</p></td>
 </tr>
 <tr>
  <td><p>11/04/2026</p></td>
  <td><p>0.02</p></td>
  <td><p>Major: v1/v2 authorize comparison, Auth Config state-token lineage, cookie and header inventory, error signaling, timing, token claims, corrected credential-hint semantics.</p></td>
 </tr>
 <tr>
  <td><p>11/04/2026</p></td>
  <td><p>0.03</p></td>
  <td><p>Minor: added the original 24 sequence and flow figures for the authentication paths.</p></td>
 </tr>
 <tr><td><p>11/05/2026</p></td><td><p>0.04</p></td><td><p>Major: clarified MFA method selection, SAS request variants and code retries, FIDO state lineage, federated return, and interrupt handling; delegated upstream protocol behavior.</p></td></tr>
</tbody></table>

# 1 Introduction

Microsoft Entra ID interactive authentication for public clients is commonly
presented as HTML sign-in pages hosted at
`https://login.microsoftonline.com`. Those pages embed a JavaScript object
named `$Config` that enumerates the JSON and form endpoints the page would
call if a browser executed the ESTS client scripts.

The same endpoints accept direct HTTP requests. A non-browser client can:

1. Start an OAuth 2.0 authorization-code request.
2. Parse `$Config` from the HTML response.
3. Call the credential, MFA challenge, polling, and completion APIs named by
   `$Config`.
4. Receive an HTTP redirect carrying an authorization `code`.
5. Hand the code to the upstream OAuth authorization-code protocol (§2.12).

ESTS exposes several interactive completion patterns that share Auth Config
discovery and diverge after GetCredentialType or after password login. The
full catalog is in [§1.3](#13-protocol-operation-sequences) and
[§6](#6-appendix-authentication-path-index). Patterns include:

- Passwordless Remote NGC (`GetOneTimeCode` / `DeviceCodeStatus`)
- Passwordless and post-password FIDO (`urlFidoLogin` / assertion POST)
- Passwordless and post-password Temporary Access Pass
- Password then SAS methods: PhoneAppNotification, CompanionAppsNotification,
  PhoneAppOTP, OneWaySMS, ConsolidatedTelephony, TwoWayVoice*
- Post-auth interrupts: KMSI, MFA ProofUp, password change (SSPR), consent
- Federated return to ESTS followed by the same MFA and interrupt handling

All authorization-code patterns conclude by delivering `code` to the
`redirect_uri` from the original authorize request (unless an interrupt is
terminal, such as consent).

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when they appear in capitals.
They specify client requirements unless a server requirement is stated
explicitly. This is an unofficial description of observed behavior, not a
Microsoft compatibility guarantee. Example timings, token formats, cookie
attributes, and HTML serialization details are observations, not fixed
protocol requirements.

## 1.1 Glossary

<table class="protocol-table"><thead>
  <tr><th><p>Term</p></th><th><p>Definition</p></th></tr>
</thead><tbody>
 <tr>
  <td><p>Auth Config / <code>$Config</code></p></td>
  <td><p>JSON object embedded in ESTS HTML responses that advertises session
  state and endpoint URLs for the current authentication step.</p></td>
 </tr>
 <tr>
  <td><p>canary</p></td>
  <td><p>CSRF / request-validation token. Appears as <code>$Config.canary</code>, as a
  form field, and as an HTTP header on some JSON APIs.</p></td>
 </tr>
 <tr>
  <td><p>ctx / sCtx / request</p></td>
  <td><p>Opaque ESTS flow context. <code>$Config.sCtx</code> is posted as <code>ctx</code> or
  <code>request</code> depending on the endpoint.</p></td>
 </tr>
 <tr>
  <td><p>flowToken / sFT</p></td>
  <td><p>Opaque ESTS flow token. <code>$Config.sFT</code> is posted as <code>flowToken</code> (or
  <code>flowtoken</code> on the MFA-registration skip resume).</p></td>
 </tr>
 <tr>
  <td><p>ESTS</p></td>
  <td><p>Microsoft Entra ID Security Token Service, hosted at
  <code>login.microsoftonline.com</code>.</p></td>
 </tr>
 <tr>
  <td><p>Remote NGC</p></td>
  <td><p>Remote Next Generation Credential challenge delivered to Microsoft
  Authenticator (push / number match).</p></td>
 </tr>
 <tr>
  <td><p>SAS</p></td>
  <td><p>Strong Authentication Service endpoints under
  <code>/common/SAS/</code>.</p></td>
 </tr>
 <tr>
  <td><p>Entropy</p></td>
  <td><p>Integer shown to the user for Authenticator number matching.</p></td>
 </tr>
 <tr>
  <td><p>IdP</p></td>
  <td><p>Identity provider.</p></td>
 </tr>
 <tr>
  <td><p>KMSI</p></td>
  <td><p>Keep me signed in; a prompt about session persistence.</p></td>
 </tr>
 <tr>
  <td><p>PKCE</p></td>
  <td><p>Proof Key for Code Exchange; binds authorization-code redemption to a client-held verifier.</p></td>
 </tr>
 <tr>
  <td><p>PRT</p></td>
  <td><p>Primary Refresh Token; used in brokered sign-in.</p></td>
 </tr>
 <tr>
  <td><p>SSPR</p></td>
  <td><p>Self-service password reset. This document describes the related APIs used for an authenticated password change.</p></td>
 </tr>
 <tr>
  <td><p>TAP</p></td>
  <td><p>Temporary Access Pass.</p></td>
 </tr>
 <tr>
  <td><p>TOTP</p></td>
  <td><p>Time-based one-time password.</p></td>
 </tr>
 <tr>
  <td><p>UPN</p></td>
  <td><p>User principal name, such as <code>user@contoso.com</code>.</p></td>
 </tr>
</tbody></table>

## 1.2 Overview

Interactive MFA over these APIs is a multi-step state machine. HTML pages
that present an authentication step embed a fresh `$Config`; intermediate
auto-submit pages are handled separately (§2.18). Clients
MUST retain `sFT`, `sCtx`, `canary`, `sessionId`, and advertised URLs from each
new `$Config`. The source of each value depends on the next endpoint;
[§2.3.4](#234-state-token-lineage) specifies exceptions to using the most
recent value, including GetCredentialType and pending EndAuth responses.

Clients MUST store cookies from ESTS `Set-Cookie` headers and send applicable,
unexpired cookies on subsequent requests, respecting their domain, path, and
security attributes ([§2.20](#220-session-cookies-and-response-headers)).

<p style="text-align:center"><a href="images/fig-01-overview.png"><img src="images/fig-01-overview.png" alt="Figure 1: Overview of ESTS interaction and upstream protocol boundaries." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 1</b>: Overview of ESTS interaction and upstream protocol boundaries.</p>

<a id="13-protocol-operation-sequences"></a>

## 1.3 Protocol Operation Sequences

ESTS offers multiple interactive authentication paths. Which path applies is
determined by offered credentials, supported client capabilities, user choice, by the
Auth Config returned after primary authentication (`arrUserProofs`, `pgid`), and
by interrupts ESTS inserts before issuing an authorization code.

All paths share a common prefix unless noted:

1. Select the tenant/cloud authority (§2.1); discovery is an external prerequisite.
2. `GET /{tenant}/oauth2/authorize` and parse `$Config`
   ([§2.2](#22-oauth-20-authorize-and-auth-config-discovery),
   [§2.3](#23-auth-config-config)).
3. `POST /common/GetCredentialType` ([§2.4](#24-getcredentialtype)).

<p style="text-align:center"><a href="images/fig-02-common-prefix.png"><img src="images/fig-02-common-prefix.png" alt="Figure 2: Common prefix: authority selection, authorize entry, Auth Config, and credential discovery." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 2</b>: Common prefix: authority selection, authorize entry, Auth Config, and credential discovery.</p>

<a id="131-path-selection-after-getcredentialtype"></a>

### 1.3.1 Path Selection After GetCredentialType

<table class="protocol-table"><thead>
  <tr><th><p>Condition</p></th><th><p>Path</p></th><th><p>Section</p></th></tr>
</thead><tbody>
 <tr>
  <td><p><code>Credentials.HasAccessPass</code> true</p></td>
  <td><p>Passwordless Temporary Access Pass</p></td>
  <td><p>§1.3.4 / §2.15</p></td>
 </tr>
 <tr>
  <td><p><code>RemoteNgcParams</code> present and non-null (<code>HasRemoteNGC</code> true)</p></td>
  <td><p>Passwordless Remote NGC (Authenticator)</p></td>
  <td><p>§1.3.2 / §2.5–§2.7</p></td>
 </tr>
 <tr>
  <td><p><code>FidoParams</code> present and non-null (request flag <code>isFidoSupported</code> was true)</p></td>
  <td><p>Passwordless FIDO</p></td>
  <td><p>§1.3.5 / §2.14</p></td>
 </tr>
 <tr>
  <td><p><code>FederationRedirectUrl</code> present</p></td>
  <td><p>External IdP sign-in, then return to ESTS (§1.3.12)</p></td>
  <td><p>§1.3.12</p></td>
 </tr>
 <tr>
  <td><p><code>IfExistsResult == 5</code> (personal Microsoft account)</p></td>
  <td><p>External personal-account sign-in (§2.19)</p></td>
  <td><p>§2.19</p></td>
 </tr>
 <tr>
  <td><p><code>HasPassword</code> true (typical organizational account)</p></td>
  <td><p>Password submission, then branch on resulting <code>pgid</code></p></td>
  <td><p>§1.3.3 / §2.8</p></td>
 </tr>
</tbody></table>

<p style="text-align:center"><a href="images/fig-03-path-selection.png"><img src="images/fig-03-path-selection.png" alt="Figure 3: Selection among usable offered credentials without a fixed attempt order." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 3</b>: Selection among usable offered credentials without a fixed attempt order.</p>

The table lists available paths, not a required order of attempts. A client
selects among offered credentials using its actual capabilities and the user's
choice. `PrefCredential` is a preference hint; its numeric value alone does
not establish usable parameters for a method. In particular, values `2` and
`7` can accompany Remote NGC, and `2` can also accompany FIDO.

For ConvergedTFA, select an offered `arrUserProofs` entry. `isDefault` marks
a preferred proof and `display` provides its label, such as a masked phone
number. An explicit user selection may choose another supported entry.
Ignore unsupported proof identifiers when finding a usable method, retaining
them as unknown extensions rather than treating the entire list as invalid.
An empty list or a list with no usable proof requires external interaction or
an optional upstream alternative (§2.19), not a guessed SAS method.

Capability flags on GetCredentialType influence the returned parameter blocks.
Advertise only capabilities the client can perform. FIDO availability, a
cross-device-capable passkey, and possession of a usable physical key are
separate facts; a server feature flag is not proof of any particular local
authenticator. Method preference and any fallback order are client policy.

### 1.3.2 Passwordless Remote NGC Sequence

1. Common prefix through GetCredentialType.
2. `POST /common/GetOneTimeCode` ([§2.5](#25-getonetimecode)).
3. Poll `POST /common/DeviceCodeStatus` until `AuthorizationState` is `2`
   ([§2.6](#26-devicecodestatus)).
4. `POST /{tenant}/login` with Remote NGC form fields
   ([§2.7](#27-login-passwordless-remote-ngc-completion)).
5. Handle any post-login interrupt ([§1.3.11](#1311-post-authentication-interrupts)),
   then exchange `code` ([§2.12](#212-authorization-code-token-exchange)).

<p style="text-align:center"><a href="images/fig-04-remote-ngc.png"><img src="images/fig-04-remote-ngc.png" alt="Figure 4: Passwordless Remote NGC challenge, polling, and completion." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 4</b>: Passwordless Remote NGC challenge, polling, and completion.</p>

### 1.3.3 Password Submission, Then Branch

1. Common prefix through GetCredentialType.
2. `POST /{tenant}/login` with username and password
   ([§2.8](#28-login-password-submission)).
3. Branch on the response:

<table class="protocol-table"><thead>
  <tr><th><p>Outcome</p></th><th><p>Next</p></th></tr>
</thead><tbody>
 <tr><td><p><code>302</code> with <code>code</code></p></td><td><p>No further challenge; upstream handoff (§2.12).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedTFA</code> with <code>arrUserProofs</code></p></td><td><p>SAS or FIDO/AccessPass proof (§1.3.6–§1.3.10).</p></td></tr>
 <tr><td><p><code>pgid=KmsiInterrupt</code></p></td><td><p>KMSI continue (§2.16).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedProofUpRedirect</code></p></td><td><p>MFA registration interrupt (§2.13 / §2.16).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedChangePassword</code></p></td><td><p>Password change / SSPR (§2.17).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedConsent</code></p></td><td><p>Application consent required (terminal for this protocol).</p></td></tr>
 <tr><td><p>Auto-submit HTML (“Working…”)</p></td><td><p>POST form action until Auth Config or redirect (§2.18).</p></td></tr>
</tbody></table>

<p style="text-align:center"><a href="images/fig-05-password-branch.png"><img src="images/fig-05-password-branch.png" alt="Figure 5: Primary password authentication and response branches." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 5</b>: Primary password authentication and response branches.</p>

### 1.3.4 Passwordless Temporary Access Pass Sequence

1. Common prefix; GetCredentialType indicates Access Pass availability.
2. Collect the Temporary Access Pass from the user (no BeginAuth).
3. `POST` to `$Config.urlPost` with Access Pass form fields
   ([§2.15](#215-temporary-access-pass-completion)).
4. Obtain `code` (possibly after interrupts) and exchange (§2.12).

<p style="text-align:center"><a href="images/fig-06-tap.png"><img src="images/fig-06-tap.png" alt="Figure 6: Temporary Access Pass completion without SAS BeginAuth." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 6</b>: Temporary Access Pass completion without SAS BeginAuth.</p>

### 1.3.5 Passwordless FIDO Sequence

1. Common prefix; GetCredentialType returns `FidoParams` (allow-list).
2. `POST {urlFidoLogin}` to obtain a FIDO challenge Auth Config
   ([§2.14.1](#2141-fidologin-challenge-bootstrap)).
3. Produce a WebAuthn/FIDO assertion locally (outside ESTS HTTP).
4. `POST` the assertion to `urlPost`
   ([§2.14.2](#2142-fido-assertion-completion)).
5. Handle any interrupts, obtain `code`, and exchange it (§2.12).

<p style="text-align:center"><a href="images/fig-07-fido-passwordless.png"><img src="images/fig-07-fido-passwordless.png" alt="Figure 7: Passwordless FIDO bootstrap and assertion state." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 7</b>: Passwordless FIDO bootstrap and assertion state.</p>

### 1.3.6 SAS PhoneAppNotification / CompanionAppsNotification (Poll)

Entered from ConvergedTFA when `arrUserProofs` contains
`PhoneAppNotification` or `CompanionAppsNotification`.

1. `POST /common/SAS/BeginAuth` with that `AuthMethodId` ([§2.9](#29-sas-beginauth)).
2. Display `Entropy` for number matching when present.
3. Poll `GET /common/SAS/EndAuth` until `Success` ([§2.10.1](#2101-endauth-poll)).
4. `POST /common/SAS/ProcessAuth` ([§2.11](#211-sas-processauth)).
5. Handle interrupts; exchange `code`.

<p style="text-align:center"><a href="images/fig-08-sas-notification.png"><img src="images/fig-08-sas-notification.png" alt="Figure 8: Notification MFA with alternative SAS polling-state patterns." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 8</b>: Notification MFA with alternative SAS polling-state patterns.</p>

### 1.3.7 SAS PhoneAppOTP (Code Entry)

Entered when `arrUserProofs` contains `PhoneAppOTP` (often with
`phoneAppOtpTypes: ["MicrosoftAuthenticatorBasedTOTP"]`).

1. `POST /common/SAS/BeginAuth` with `AuthMethodId=PhoneAppOTP`.
2. Collect the TOTP from the authenticator app.
3. `POST /common/SAS/EndAuth` with `Method=EndAuth` and
   `AdditionalAuthData` set to the OTP ([§2.10.2](#2102-endauth-otp-submission)).
4. `POST /common/SAS/ProcessAuth` with `mfaAuthMethod=PhoneAppOTP`.
5. Handle interrupts; exchange `code`.

<p style="text-align:center"><a href="images/fig-09-sas-otp.png"><img src="images/fig-09-sas-otp.png" alt="Figure 9: OTP submission, recoverable code rejection, and completion." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 9</b>: OTP submission, recoverable code rejection, and completion.</p>

### 1.3.8 SAS SMS / Consolidated Telephony

Entered when `arrUserProofs` contains `OneWaySMS` or
`ConsolidatedTelephony`. `display` often carries a masked phone number.

1. `POST /common/SAS/BeginAuth` with the selected `AuthMethodId`.
2. Collect the SMS code.
3. `POST /common/SAS/EndAuth` with `AdditionalAuthData` set to the SMS code.
4. `POST /common/SAS/ProcessAuth`. For `ConsolidatedTelephony`, the
   `mfaAuthMethod` form field MUST be posted as `OneWaySMS` (ESTS rejects
   `ConsolidatedTelephony` on ProcessAuth).
5. Handle interrupts; exchange `code`.

<p style="text-align:center"><a href="images/fig-10-sas-sms.png"><img src="images/fig-10-sas-sms.png" alt="Figure 10: SMS and ConsolidatedTelephony method mapping." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 10</b>: SMS and ConsolidatedTelephony method mapping.</p>

### 1.3.9 SAS Voice Call Methods

Entered when `arrUserProofs` contains `TwoWayVoiceMobile`,
`TwoWayVoiceAlternateMobile`, or `TwoWayVoiceOffice`.

1. `POST /common/SAS/BeginAuth` with the voice `AuthMethodId`.
2. Poll `GET /common/SAS/EndAuth` until the call is answered / approved
   (same poll contract as PhoneAppNotification).
3. `POST /common/SAS/ProcessAuth` with the same `mfaAuthMethod`.
4. Handle interrupts; exchange `code`.

<p style="text-align:center"><a href="images/fig-11-sas-voice.png"><img src="images/fig-11-sas-voice.png" alt="Figure 11: Voice challenge and bounded approval polling." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 11</b>: Voice challenge and bounded approval polling.</p>

### 1.3.10 FIDO or Access Pass From ConvergedTFA

After password login, `arrUserProofs` MAY list `FidoKey` or `AccessPass`
alongside SAS methods.

- __FidoKey__: Bootstrap via `urlFidoLogin` using `arrFidoAllowList` from the
  ConvergedTFA Auth Config (or GetCredentialType `FidoParams.AllowList`),
  then complete with assertion POST ([§2.14](#214-fido-authentication)).
  BeginAuth is not used for FidoKey.
- __AccessPass__: Collect TAP and POST to `urlPost` ([§2.15](#215-temporary-access-pass-completion)).
  BeginAuth is not used for AccessPass.

<p style="text-align:center"><a href="images/fig-12-fido-from-tfa.png"><img src="images/fig-12-fido-from-tfa.png" alt="Figure 12: FIDO selected from ConvergedTFA, retaining initiating state." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 12</b>: FIDO selected from ConvergedTFA, retaining initiating state.</p>

<a id="1311-post-authentication-interrupts"></a>

### 1.3.11 Post-Authentication Interrupts

After primary authentication or proof completion (including ProcessAuth,
passwordless login, and FIDO/TAP), ESTS may return another proof page,
an interrupt, or a continuation instead of an authorization response:

<table class="protocol-table"><thead>
  <tr><th><p>pgid / condition</p></th><th><p>Wire handling</p></th></tr>
</thead><tbody>
 <tr><td><p><code>ConvergedTFA</code> with <code>arrUserProofs</code></p></td><td><p>Another proof is required. Select a usable offered method with this page's state (§1.3.1); do not treat the preceding credential completion as final authorization.</p></td></tr>
 <tr>
  <td><p><code>KmsiInterrupt</code></p></td>
  <td><p>POST <code>urlPost</code> with <code>LoginOptions=1</code>, <code>ctx</code>, <code>flowToken</code>, <code>canary</code>
  (<a href="#216-kmsi-and-proofup-continue-posts">§2.16</a>).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedProofUpRedirect</code> with <code>urlSkipMfaRegistration</code></p></td>
  <td><p>Either complete registration (out of scope) or POST skip resume
  (<a href="#213-skip-mfa-registration-resume">§2.13</a>). When remaining skip days
  are advertised, a <code>LoginOptions=1</code> continue POST on the current
  <code>urlPost</code> MAY also advance the flow (<a href="#216-kmsi-and-proofup-continue-posts">§2.16</a>).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedChangePassword</code></p></td>
  <td><p>Password change via SSPR begin/poll endpoints from Auth Config
  (<a href="#217-password-change-sspr">§2.17</a>).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedConsent</code></p></td>
  <td><p>Admin/user consent required; no further MFA API advances the flow.</p></td>
 </tr>
 <tr>
  <td><p>Auto-submit / “Working…” HTML</p></td>
  <td><p>Parse and POST the HTML form until redirect or Auth Config
  (<a href="#218-intermediate-auto-submit-html">§2.18</a>).</p></td>
 </tr>
</tbody></table>

<p style="text-align:center"><a href="images/fig-13-interrupts.png"><img src="images/fig-13-interrupts.png" alt="Figure 13: Response dispatch across MFA, interrupts, continuations, and errors." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 13</b>: Response dispatch across MFA, interrupts, continuations, and errors.</p>

<p style="text-align:center"><a href="images/fig-14-kmsi.png"><img src="images/fig-14-kmsi.png" alt="Figure 14: KMSI continuation." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 14</b>: KMSI continuation.</p>

<p style="text-align:center"><a href="images/fig-15-proofup.png"><img src="images/fig-15-proofup.png" alt="Figure 15: ProofUp skip-resume and postponement variants." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 15</b>: ProofUp skip-resume and postponement variants.</p>

<p style="text-align:center"><a href="images/fig-16-sspr.png"><img src="images/fig-16-sspr.png" alt="Figure 16: Password-change job and alternative confirmation encodings." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 16</b>: Password-change job and alternative confirmation encodings.</p>

<p style="text-align:center"><a href="images/fig-17-autosubmit.png"><img src="images/fig-17-autosubmit.png" alt="Figure 17: Bounded continuation-form handling." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 17</b>: Bounded continuation-form handling.</p>

### 1.3.12 Federated Identities

`Credentials.FederationRedirectUrl` directs primary authentication to an
external IdP. IdP credential collection and assertion creation are outside
ESTS. The federated result can return to ESTS rather than requiring a new
OAuth grant.

For the WS-Federation return path, the eSTS receiving endpoint is
`https://{authority-host}/login.srf` on the authority origin, without a tenant
path prefix. Submit the returned sign-in form using the upstream
[WS-Federation passive requestor protocol](https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html)
message format; preserve the returned assertion and context rather than
constructing new values. Preserve applicable ESTS cookies across this return.

The response can deliver an authorization response, an interstitial, an
interrupt, or ConvergedTFA with `arrUserProofs`. In the last case, use the new
MFA page state and the same SAS, FIDO, or TAP paths described for password
sign-in. A federated assertion does not universally remove the need for an
ESTS MFA challenge. An unsupported IdP interaction may require external
browser interaction or an optional upstream alternative (§2.19).

<p style="text-align:center"><a href="images/fig-18-consumers-federated.png"><img src="images/fig-18-consumers-federated.png" alt="Figure 18: Federated return to ESTS and external account routing." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 18</b>: Federated return to ESTS and external account routing.</p>

### 1.3.13 Device Authorization Grant (External Alternative)

For an alternate OAuth flow, see the upstream references in §2.19. Its
verification and token polling are outside the ESTS interaction described here.

### 1.3.14 Requesting MFA on Authorize

The v1 ESTS entry accepts `amr_values=ngcmfa` to request MFA. This is a
request for an authentication outcome, not a command to choose Remote NGC
or to trigger a fresh push regardless of existing session state. Tenant policy
still determines the permitted methods and authentication strength.

The parameter is also defined in
[MS-OAPX §2.2.2.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapx/0fc398ca-88d0-4118-ae60-c3033e396e60)
for AD FS. That upstream definition does not by itself establish every value
or precedence rule for ESTS; this document specifies only the ESTS use above.

## 1.4 Completeness of Field Descriptions

The request fields and response members needed for each ESTS operation are
described below. Responses may contain additional fields; ignore fields not
consumed by the exchange and do not require optional example metadata. A
request pattern does not establish that arbitrary field combinations work.

Examples and Figures 1–23 illustrate the exchanges. GUIDs, opaque values,
HTML serialization, and timings are representative, not constants. The
endpoint-specific text defines state selection and failure handling.


# 2 Protocol Details

<a id="21-federation-provider-discovery"></a>

## 2.1 Authority Discovery (External Prerequisite)

Select the tenant and cloud authority before starting ESTS interaction.
[Microsoft authority and tenant guidance](https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-application-configuration#authority)
describes the public authority choices. Optional Office federation-provider
discovery is an external service, not an ESTS MFA exchange, and its HTTP
contract is outside this specification. Federation realm discovery and a
federated return to ESTS are distinct operations (§1.3.12).

<a id="22-oauth-20-authorize-and-auth-config-discovery"></a>

## 2.2 OAuth 2.0 Authorize and Auth Config Discovery

### 2.2.1 authorize

#### 2.2.1.1 GET

This method is transported by an HTTP GET to ESTS.

##### 2.2.1.1.1 Request

<pre><code>GET https://login.microsoftonline.com/{tenant}/oauth2/authorize?{query}
</code></pre>

An upstream OAuth authorization request enters the ESTS page interaction.
This document describes the v1 `/{tenant}/oauth2/authorize` entry point with
`response_type=code`. Standard request parameters and response validation are
specified by [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1),
[OpenID Connect Core §3.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
and Microsoft's applicable endpoint documentation (§2.2.2).

The following additional parameters are relevant to ESTS interaction:

<table class="protocol-table"><thead>
<tr><th><p>Parameter</p></th><th><p>ESTS use</p></th></tr>
</thead><tbody>
<tr><td><p>client-request-id</p></td><td><p>Client correlation GUID; also used by discovery requests.</p></td></tr>
<tr><td><p>sso_reload</p></td><td><p><code>True</code> occurs on interactive v1 entry requests; not an MFA proof.</p></td></tr>
<tr><td><p>caller_app_client_id / caller_app_redirect_uri</p></td><td><p>Calling application identifiers in brokered requests; not required for direct clients.</p></td></tr>
<tr><td><p>amr_values</p></td><td><p><code>ngcmfa</code> requests MFA on the v1 entry path; §1.3.14 describes its boundary with upstream extensions.</p></td></tr>
</tbody></table>

MFA requirements depend on the target resource, request, existing session,
and tenant policy. No particular application ID, redirect URI, or scope
ordering is required by the MFA APIs. A browser User-Agent can affect the
capabilities advertised by ESTS (§2.20).

##### 2.2.1.1.2 Response Body

On interactive sign-in the response is `200` with `Content-Type: text/html`
and one or more `Set-Cookie` headers. The HTML body contains a script block
that assigns the Auth Config object:

<pre><code>$Config={...};
</code></pre>

The observed script element has the following structure:

<pre><code>&lt;script type="text/javascript" nonce='{nonce}'&gt;//&lt;![CDATA[
$Config={...JSON object...};
//]]&gt;&lt;/script&gt;
</code></pre>

The script wrapper is an example, not a fixed extraction delimiter. Other
script elements and references to `$Config` can occur in the page. JSON
escapes such as `\u0026` in URLs are decoded by the JSON parser.

##### 2.2.1.1.3 Processing Details

The client MUST:

1. Persist cookies from the response.
2. Locate the `$Config=` assignment in a `<script>` element.
3. Parse the JSON object that follows through its matching closing `}`,
   respecting JSON string quoting and escapes. Do not rely on a fixed number
   of trailing characters, line endings, or CDATA comment markers, and do not
   execute the script.
4. Retain the fields listed in [§2.3](#23-auth-config-config) for subsequent
   calls.

Initial authorize responses include `sErrorCode: "50058"` and
`arrValErrs: ["50058"]` (user not signed in) on ConvergedSignIn. That value describes page state for the HTML UI and MUST NOT be
treated as fatal at this step. On later pages, interpret error fields together with page
state and advertised actions (§2.21).

The authorize response also sets the initial cookie set described in
[§2.20](#220-session-cookies-and-response-headers) and returns the first
`sFT`, `sCtx`, `canary`, `apiCanary`, `sCrossDomainCanary` and `sessionId`.

<a id="222-v1-and-v2-authorize-differences"></a>

### 2.2.2 OAuth Endpoint Versions (Upstream)

The interactive exchanges in this specification use the v1 authorize entry
point; follow-on URLs come from the current Auth Config rather than being
constructed by adding an OAuth endpoint-version suffix. Do not infer v2
support for an ESTS extension from the existence of a v2 OAuth endpoint.
For the documented authorization and token contracts, consult
[Microsoft's v1 OAuth protocol](https://learn.microsoft.com/en-us/previous-versions/azure/active-directory/azuread-dev/v1-protocols-oauth-code)
and [v2 authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).

<p style="text-align:center"><a href="images/fig-19-v1-v2.png"><img src="images/fig-19-v1-v2.png" alt="Figure 19: ESTS entry, interaction, and upstream OAuth handoff." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 19</b>: ESTS entry, interaction, and upstream OAuth handoff.</p>

<a id="223-client-identifiers-and-redirect-uris"></a>

### 2.2.3 Client Identifiers and Redirect URIs (Upstream)

Use the identifiers and registered redirect URI of the requesting application.
Application registration and redirect validation are governed by the upstream
OAuth contract; they are not a method-selection mechanism in ESTS MFA.

<a id="23-auth-config-config"></a>

## 2.3 Auth Config (`$Config`)

Auth Config is not a standalone HTTP resource. It is the control plane for
ESTS interactive flows and is reissued on authentication and interrupt pages.
Intermediate auto-submit pages may instead contain only a continuation form.

<a id="231-common-fields"></a>

### 2.3.1 Common Fields

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Type</p></th><th><p>Description</p></th></tr>
</thead><tbody>
 <tr><td><p>sessionId</p></td><td><p>string</p></td><td><p>Page session identifier; used by the retained-state polling pattern. Can differ from SAS <code>SessionId</code>. Do not substitute a server trace ID for this field (§2.3.4).</p></td></tr>
 <tr><td><p>sFT</p></td><td><p>string</p></td><td><p>Flow token. Posted as <code>flowToken</code>.</p></td></tr>
 <tr><td><p>sFTName</p></td><td><p>string</p></td><td><p>Form field name for the flow token (value <code>flowToken</code>).</p></td></tr>
 <tr><td><p>sCtx</p></td><td><p>string</p></td><td><p>Flow context. Posted as <code>ctx</code> or <code>request</code>.</p></td></tr>
 <tr><td><p>canary</p></td><td><p>string</p></td><td><p>Request validation token.</p></td></tr>
 <tr><td><p>apiCanary</p></td><td><p>string</p></td><td><p>API request-validation token; used as the SAS <code>canary</code> header in an alternative request form (§2.9).</p></td></tr>
 <tr><td><p>correlationId</p></td><td><p>string</p></td><td><p>Correlation GUID.</p></td></tr>
 <tr><td><p>sTenantId</p></td><td><p>string</p></td><td><p>Tenant GUID.</p></td></tr>
 <tr><td><p>pgid</p></td><td><p>string</p></td><td><p>Page identifier describing the current interrupt. See
 <a href="#233-page-identifiers-pgid">§2.3.3</a>.</p></td></tr>
 <tr><td><p>urlPost</p></td><td><p>string</p></td><td><p>URL for the next form POST that advances the flow.</p></td></tr>
 <tr><td><p>urlGetCredentialType</p></td><td><p>string</p></td><td><p>URL for GetCredentialType. Example:
 <code>https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US</code>.</p></td></tr>
 <tr><td><p>urlGetOneTimeCode</p></td><td><p>string</p></td><td><p>URL for GetOneTimeCode.</p></td></tr>
 <tr><td><p>urlSessionState</p></td><td><p>string</p></td><td><p>URL for DeviceCodeStatus polling.</p></td></tr>
 <tr><td><p>urlBeginAuth</p></td><td><p>string</p></td><td><p>URL for SAS BeginAuth. Present on a SAS MFA page.</p></td></tr>
 <tr><td><p>urlEndAuth</p></td><td><p>string</p></td><td><p>URL for SAS EndAuth. Present on a SAS MFA page.</p></td></tr>
 <tr><td><p>arrUserProofs</p></td><td><p>array</p></td><td><p>Available MFA methods after primary authentication. See
 <a href="#232-arruserproofs">§2.3.2</a>.</p></td></tr>
 <tr><td><p>iMaxPollAttempts</p></td><td><p>number</p></td><td><p>Maximum EndAuth poll attempts when advertised (for example <code>10</code>).</p></td></tr>
 <tr><td><p>iPollingInterval</p></td><td><p>number</p></td><td><p>Polling interval. On ConvergedTFA this is milliseconds (value
 <code>5000</code>; clients poll EndAuth about every 5.1–5.3 s). On ConvergedSignIn
 the value is <code>1</code> and the page does not state a unit; clients poll DeviceCodeStatus
 about every 5.1 s and ESTS accepts that cadence.</p></td></tr>
 <tr><td><p>urlSkipMfaRegistration</p></td><td><p>string</p></td><td><p>Resume URL that skips MFA method registration interrupt.</p></td></tr>
 <tr><td><p>iRemainingDaysToSkipMfaRegistration</p></td><td><p>number</p></td><td><p>Remaining days allowed to postpone MFA registration, when present.</p></td></tr>
 <tr><td><p>sErrorCode</p> / <p>iErrorCode</p></td><td><p>string / number</p></td><td><p>Error or interrupt identifier. <code>sErrorCode</code> can be a numeric string or a symbolic value such as <code>InvalidAccessPass</code>.</p></td></tr>
 <tr><td><p>sErrTxt</p> / <p>strServiceExceptionMessage</p></td><td><p>string</p></td><td><p>Human-readable error text when present.</p></td></tr>
 <tr><td><p>urlFidoLogin</p></td><td><p>string</p></td><td><p>FIDO challenge bootstrap endpoint when FIDO is offered. Preserve the initiating page's completion endpoint and state as specified in §2.14.</p></td></tr>
 <tr><td><p>sFidoChallenge</p></td><td><p>string</p></td><td><p>FIDO challenge material when present on the sign-in page.</p></td></tr>
 <tr><td><p>arrFidoAllowList</p></td><td><p>array</p></td><td><p>Array of serialized FIDO allow-list entries when present; the bootstrap <code>credentialsJson</code> carries one entry unchanged.</p></td></tr>
 <tr><td><p>sCrossDomainCanary</p></td><td><p>string</p></td><td><p>Canary used when posting FIDO assertions.</p></td></tr>
 <tr><td><p>fEnableNumberMatching</p></td><td><p>boolean</p></td><td><p>Whether Authenticator number matching is enabled for the tenant UX.</p></td></tr>
 <tr><td><p>sSessionIdentifierName</p></td><td><p>string</p></td><td><p>Value <code>code</code>; names the Remote NGC session form field.</p></td></tr>
 <tr><td><p>sCanaryTokenName</p></td><td><p>string</p></td><td><p>Value <code>canary</code>; names the canary form field.</p></td></tr>
 <tr><td><p>iPollingTimeout</p></td><td><p>number</p></td><td><p><code>300</code> on ConvergedSignIn: the overall Remote NGC polling window. The unit is not stated; 300 is consistent with seconds.</p></td></tr>
 <tr><td><p>iMaxPollErrors</p></td><td><p>number</p></td><td><p><code>5</code> on ConvergedSignIn: transport or server errors the page tolerates while polling.</p></td></tr>
 <tr><td><p>iRemoteNgcPollingType</p></td><td><p>number</p></td><td><p>Value <code>2</code>. Selects the polling mechanism the page uses for Remote NGC; value <code>2</code> corresponds to <code>urlSessionState</code> DeviceCodeStatus polling.</p></td></tr>
 <tr><td><p>iAllowedIdentities</p></td><td><p>number</p></td><td><p>Value <code>2</code>. Posted as <code>allowedIdentities</code> to <code>urlFidoLogin</code>.</p></td></tr>
 <tr><td><p>urlCancel</p></td><td><p>string</p></td><td><p>The <code>redirect_uri</code> with <code>error=access_denied&amp;error_subcode=cancel</code> appended. Navigating to it is the protocol's cancellation signal.</p></td></tr>
 <tr><td><p>urlResume</p></td><td><p>string</p></td><td><p>ConvergedSignIn: <code>…/{tenant}/resume?ctx={sCtx}</code>; ConvergedTFA: <code>…/{tenant}/resume</code> with no query.</p></td></tr>
 <tr><td><p>browser</p></td><td><p>object</p></td><td><p>ESTS' parse of the request <code>User-Agent</code>: <code>b.name</code>, <code>b.major</code>, <code>os.name</code>, plus capability flags. For example <code>Firefox</code> 131 / <code>Linux</code> for a Firefox 131 user agent string. Server-side capability decisions (for example FIDO) are evaluated against this value.</p></td></tr>
</tbody></table>

The fields above support these exchanges. Other UI flags, string tables,
branding, and telemetry fields may be ignored here. Their presence or absence
does not establish support for a new authentication mechanism.

<a id="232-arruserproofs"></a>

### 2.3.2 arrUserProofs

Each element describes one MFA proof the user may satisfy:

<pre><code class="lang-json">{
  "authMethodId": "PhoneAppNotification",
  "data": "PhoneAppNotification",
  "display": "",
  "isDefault": true,
  "isLocationAware": false
}
</code></pre>

`authMethodId` values include:

<table class="protocol-table"><thead>
  <tr><th><p>authMethodId</p></th><th><p>Challenge style</p></th></tr>
</thead><tbody>
 <tr><td><p>PhoneAppNotification</p></td><td><p>Authenticator push / number match; poll EndAuth.</p></td></tr>
 <tr><td><p>CompanionAppsNotification</p></td><td><p>Companion-app approval; poll EndAuth using the selected method ID.</p></td></tr>
 <tr><td><p>PhoneAppOTP</p></td><td><p>TOTP from Authenticator; POST EndAuth with AdditionalAuthData. May
 include <code>phoneAppOtpTypes</code> such as
 <code>MicrosoftAuthenticatorBasedTOTP</code>.</p></td></tr>
 <tr><td><p>OneWaySMS</p></td><td><p>SMS code; POST EndAuth with AdditionalAuthData.</p></td></tr>
 <tr><td><p>ConsolidatedTelephony</p></td><td><p>Telephony umbrella; ProcessAuth posts
 <code>mfaAuthMethod=OneWaySMS</code>.</p></td></tr>
 <tr><td><p>TwoWayVoiceMobile</p> / <p>TwoWayVoiceAlternateMobile</p> / <p>TwoWayVoiceOffice</p></td>
 <td><p>Voice call confirmation; poll EndAuth.</p></td></tr>
 <tr><td><p>FidoKey</p></td><td><p>FIDO2 / security key assertion posted to urlPost / FIDO endpoints.</p></td></tr>
 <tr><td><p>AccessPass</p></td><td><p>Temporary Access Pass posted to urlPost.</p></td></tr>
</tbody></table>

<a id="233-page-identifiers-pgid"></a>

### 2.3.3 Page Identifiers (`pgid`)

<table class="protocol-table"><thead>
  <tr><th><p>pgid</p></th><th><p>Meaning</p></th></tr>
</thead><tbody>
 <tr><td><p>ConvergedSignIn</p></td><td><p>Initial username / password page. Advertises GetCredentialType /
 GetOneTimeCode / DeviceCodeStatus.</p></td></tr>
 <tr><td><p>ConvergedTFA</p></td><td><p>MFA interrupt after primary authentication. Advertises urlBeginAuth, urlEndAuth,
 arrUserProofs; urlPost points at ProcessAuth.</p></td></tr>
 <tr><td><p>ConvergedProofUpRedirect</p></td><td><p>Registration interrupt. Can advertise a skip URL without remaining-days metadata, or a postponement option. <code>sCtx</code> can be absent; <code>urlPost</code> can point to a separate registration host (§2.13, §2.16).</p></td></tr>
 <tr><td><p>KmsiInterrupt</p></td><td><p>“Keep me signed in” prompt.</p></td></tr>
 <tr><td><p>ConvergedChangePassword</p></td><td><p>Password change required.</p></td></tr>
 <tr><td><p>ConvergedConsent</p></td><td><p>Application consent required.</p></td></tr>
</tbody></table>

<a id="234-state-token-lineage"></a>

### 2.3.4 State Token Lineage

State values are opaque. Retain the page state separately from SAS response
state and FIDO bootstrap state. Replacing every stored field whenever a
response arrives loses values needed by later requests. The following table
specifies the demonstrated request patterns; it does not require a server to
accept arbitrary mixtures of them.

<table class="protocol-table"><thead>
<tr><th><p>Request</p></th><th><p>Values and provenance</p></th></tr>
</thead><tbody>
<tr><td><p>GetCredentialType</p></td><td><p><code>flowToken=sFT</code>, <code>originalRequest=sCtx</code> from the entry page.</p></td></tr>
<tr><td><p>GetOneTimeCode</p></td><td><p>Entry-page <code>sFT</code>, <code>sCtx</code>, and <code>canary</code>; discovery's Remote NGC identifier as <code>OldDeviceCode</code>.</p></td></tr>
<tr><td><p>DeviceCodeStatus</p></td><td><p>Entry-page <code>canary</code>; identifier returned by GetOneTimeCode in both query and body. No flow token or context.</p></td></tr>
<tr><td><p>login (Remote NGC)</p></td><td><p>Entry-page <code>sFT</code>, <code>sCtx</code>, <code>canary</code>; GetOneTimeCode's identifier and entropy.</p></td></tr>
<tr><td><p>login (password)</p></td><td><p>Entry-page <code>sFT</code>, <code>sCtx</code>, <code>canary</code>. These paths do not require replacing them with discovery's <code>FlowToken</code> or <code>apiCanary</code>.</p></td></tr>
<tr><td><p>BeginAuth</p></td><td><p>MFA-page <code>sFT</code> and <code>sCtx</code>; SAS canary-header choice from that page (§2.9).</p></td></tr>
<tr><td><p>EndAuth GET: retained-state pattern</p></td><td><p>MFA-page <code>sessionId</code> as <code>x-ms-sessionId</code>; BeginAuth <code>FlowToken</code>/<code>Ctx</code> retained across pending polls.</p></td></tr>
<tr><td><p>EndAuth GET: response-state pattern</p></td><td><p>BeginAuth <code>SessionId</code>/<code>FlowToken</code>/<code>Ctx</code> for the first poll; preceding SAS response values for later polls.</p></td></tr>
<tr><td><p>EndAuth POST: code entry</p></td><td><p>BeginAuth <code>SessionId</code>/<code>FlowToken</code>/<code>Ctx</code> in the JSON body; SAS canary header (§2.10.2).</p></td></tr>
<tr><td><p>ProcessAuth</p></td><td><p>Successful EndAuth <code>FlowToken</code> and <code>Ctx</code> as <code>flowToken</code> and <code>request</code>; MFA-page <code>canary</code>.</p></td></tr>
<tr><td><p>FIDO bootstrap and assertion</p></td><td><p>Keep initiating page state; bootstrap response supplies challenge, cross-domain canary, and completion session ID. See §2.14.</p></td></tr>
<tr><td><p>ProofUp skip resume</p></td><td><p>ProofUp <code>sFT</code> as lowercase <code>flowtoken</code>, ProofUp <code>canary</code>; preceding ProcessAuth <code>request</code> as <code>ctx</code> when ProofUp lacks <code>sCtx</code>.</p></td></tr>
<tr><td><p>KMSI / ProofUp postponement</p></td><td><p>Endpoint-specific page and preceding-state selection in §2.16.</p></td></tr>
<tr><td><p>SSPR</p></td><td><p>Begin with password-change page state, then carry the preceding job response's context, flow token, and routing values (§2.17).</p></td></tr>
</tbody></table>

A pending EndAuth response may return a different flow token even when the
retained-state pattern continues to work. This does not establish that
pending tokens are universally ignorable. Choose one documented polling
pattern for a challenge; successful EndAuth values are used for completion
in either pattern.

Canaries and tokens can contain `+`, `/`, and `=`. Preserve their values and
use the endpoint's JSON or form encoding. Do not parse their internal shape,
assume fixed lengths, or impose server validity requirements from example
reuse. EndAuth GET carries potentially large opaque state in headers; clients
and intermediaries must accommodate those values without truncation.

<p style="text-align:center"><a href="images/fig-20-token-lineage.png"><img src="images/fig-20-token-lineage.png" alt="Figure 20: Page state, alternative SAS polling patterns, and completion state." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 20</b>: Page state, alternative SAS polling patterns, and completion state.</p>

<a id="24-getcredentialtype"></a>

## 2.4 GetCredentialType

### 2.4.1 GetCredentialType

#### 2.4.1.1 POST

This method is transported by an HTTP POST.

##### 2.4.1.1.1 Request

<pre><code>POST {urlGetCredentialType}
</code></pre>

Typical URL:
`https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US`

Request headers:

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>Content-Type</p></td><td><p>application/json; charset=UTF-8</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>Correlation GUID. Clients send the authorize <code>client-request-id</code>. ESTS echoes it in the response header of the same name.</p></td></tr>
 <tr><td><p>Cookie</p></td><td><p>Cookies from prior ESTS responses</p></td></tr>
 <tr><td><p>User-Agent / Accept</p></td><td><p>A browser <code>User-Agent</code> string, and <code>*/*</code>. See <a href="#220-session-cookies-and-response-headers">§2.20</a>.</p></td></tr>
</tbody></table>

Example request body for a client supporting all illustrated credential paths.
Set capability flags to match the client; the all-true values below are not
requirements for every implementation:

<pre><code class="lang-json">{
  "username": "user@contoso.com",
  "isOtherIdpSupported": true,
  "checkPhones": true,
  "isRemoteNGCSupported": true,
  "isCookieBannerShown": false,
  "isFidoSupported": true,
  "isAccessPassSupported": true,
  "originalRequest": "{sCtx}",
  "flowToken": "{sFT}"
}
</code></pre>

__username__: User principal name.

__originalRequest__: The current `$Config.sCtx`.

__flowToken__: The current `$Config.sFT`.

__isRemoteNGCSupported__ / __isFidoSupported__ / __isAccessPassSupported__:
Capability flags. When true, ESTS MAY return corresponding credential
parameters.

##### 2.4.1.1.2 Response Body

<pre><code class="lang-json">{
  "Username": "user@contoso.com",
  "Display": "user@contoso.com",
  "IfExistsResult": 0,
  "IsUnmanaged": false,
  "ThrottleStatus": 0,
  "Credentials": {
    "PrefCredential": 2,
    "HasPassword": true,
    "HasRemoteNGC": true,
    "RemoteNgcParams": {
      "SessionIdentifier": "string",
      "Entropy": 94,
      "DefaultType": 1,
      "Application": "client-id-guid"
    },
    "FidoParams": null,
    "QrCodePinParams": null,
    "SasParams": null,
    "CertAuthParams": null,
    "GoogleParams": null,
    "FacebookParams": null,
    "OtcNotAutoSent": false
  },
  "DfpProperties": {},
  "EstsProperties": {
    "UserTenantBranding": null,
    "DomainType": 3
  },
  "FlowToken": "string",
  "IsSignupDisallowed": true,
  "apiCanary": "string"
}
</code></pre>

The example above is the response for a Remote NGC-capable account. The
response for a password-only
account can instead return `PrefCredential: 1` and `RemoteNgcParams: null`,
with `HasRemoteNGC` and `IsSignupDisallowed` absent. The following `Credentials` members are present only when applicable
and are absent in the example: `HasAccessPass`, `HasFido`,
`FederationRedirectUrl`. Clients MUST treat an absent member as false/null.
`IsUnmanaged`, `DfpProperties`, `EstsProperties.DomainType`
(for example `3`), `Display` and `OtcNotAutoSent` are returned but do not
influence any later request.

Persist cookie updates and retain the returned control fields needed by the
selected path. Cookie names and diagnostic headers are described in §2.20.

##### 2.4.1.1.3 Processing Details

__IfExistsResult__:

<table class="protocol-table"><thead>
  <tr><th><p>Value</p></th><th><p>Meaning</p></th></tr>
</thead><tbody>
 <tr><td><p>0</p></td><td><p>Account exists for this domain.</p></td></tr>
 <tr><td><p>1</p></td><td><p>Account does not exist.</p></td></tr>
 <tr><td><p>2</p></td><td><p>Throttled.</p></td></tr>
 <tr><td><p>4</p></td><td><p>Server error.</p></td></tr>
 <tr><td><p>5</p></td><td><p>Exists as a different IdP / personal Microsoft account.</p></td></tr>
 <tr><td><p>6</p></td><td><p>Exists with both domain and alternate IdP support.</p></td></tr>
</tbody></table>

A client MUST abort the sign-in when the value is `1` and SHOULD retry later
when it is `2` (throttling).

__ThrottleStatus__: A non-zero value indicates ESTS is rate-limiting the
request. A healthy response carries `0`.

__PrefCredential__: Preferred credential hint. For example `1` with a
password-only account and `2` with a Remote NGC-capable account.
See [§1.3.1](#131-path-selection-after-getcredentialtype) for why the numeric
value alone MUST NOT be used to infer usable method parameters.

__RemoteNgcParams__: When present, passwordless Authenticator MFA MAY proceed
via GetOneTimeCode and DeviceCodeStatus. `SessionIdentifier` identifies the challenge. Use the parameters returned by
GetOneTimeCode for polling and completion; display its `Entropy`.

__FlowToken__: Flow token returned by GetCredentialType. In the Remote NGC
and password paths documented here, subsequent requests retain the
authorize-time `sFT` instead; see [§2.3.4](#234-state-token-lineage).

__FidoParams__: When present, contains `AllowList` and optionally
`HasCrossDeviceCapablePasskey`.

<a id="25-getonetimecode"></a>

## 2.5 GetOneTimeCode

### 2.5.1 GetOneTimeCode

#### 2.5.1.1 POST

This method is transported by an HTTP POST. It triggers delivery of a Remote
NGC challenge to Microsoft Authenticator.

##### 2.5.1.1.1 Request

<pre><code>POST {urlGetOneTimeCode}
</code></pre>

Typical URL: `https://login.microsoftonline.com/common/GetOneTimeCode`

Request headers:

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>Content-Type</p></td><td><p>application/json; charset=UTF-8</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>Correlation GUID</p></td></tr>
 <tr><td><p>canary</p></td><td><p><code>$Config.canary</code></p></td></tr>
 <tr><td><p>Cookie</p></td><td><p>ESTS cookies</p></td></tr>
</tbody></table>

Request body:

<pre><code class="lang-json">{
  "Channel": "Authenticator",
  "FlowToken": "{sFT}",
  "OldDeviceCode": "{RemoteNgcParams.SessionIdentifier}",
  "OriginalRequest": "{sCtx}"
}
</code></pre>

##### 2.5.1.1.2 Response Body

<pre><code class="lang-json">{
  "RemoteNgcParams": {
    "SessionIdentifier": "string",
    "Entropy": 94,
    "DefaultType": 3,
    "UserCode": "LRRW5EA8"
  }
}
</code></pre>

Errors MAY appear as:

<pre><code class="lang-json">{
  "error": { "message": "string" }
}
</code></pre>

##### 2.5.1.1.3 Processing Details

The returned `SessionIdentifier` MUST be used as `DeviceCode` when polling
DeviceCodeStatus and as the `code` / `psRNGCSLK` fields when completing login.
The response can retain the identifier and entropy supplied by discovery,
but clients MUST use the returned values rather than depend on equality.
`DefaultType` may differ from its discovery value. The request carries `client-request-id` equal to the authorize
value and `canary` equal to `$Config.canary`; a `User-Agent` header is not required.
The first DeviceCodeStatus poll MAY follow GetOneTimeCode immediately.

`Entropy` is the number the user confirms in Authenticator when number
matching is enabled. `UserCode` MAY also be returned.

<a id="26-devicecodestatus"></a>

## 2.6 DeviceCodeStatus

### 2.6.1 DeviceCodeStatus

#### 2.6.1.1 POST

This method is transported by an HTTP POST. It polls for Remote NGC approval.

##### 2.6.1.1.1 Request

<pre><code>POST {urlSessionState}?code={SessionIdentifier}
</code></pre>

Typical URL: `https://login.microsoftonline.com/common/DeviceCodeStatus`

Request headers:

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>Content-Type</p></td><td><p>application/json</p></td></tr>
 <tr><td><p>canary</p></td><td><p><code>$Config.canary</code></p></td></tr>
 <tr><td><p>Cookie</p></td><td><p>ESTS cookies</p></td></tr>
 <tr><td><p>User-Agent</p></td><td><p>Optional (a browser string is accepted); no flow token or ctx is sent.</p></td></tr>
</tbody></table>

Request body:

<pre><code class="lang-json">{
  "DeviceCode": "{SessionIdentifier}"
}
</code></pre>

The same SessionIdentifier is passed both as the `code` query parameter and
as `DeviceCode` in the JSON body.

##### 2.6.1.1.2 Response Body

<pre><code class="lang-json">{
  "AuthorizationState": 0
}
</code></pre>

__AuthorizationState__:

<table class="protocol-table"><thead>
  <tr><th><p>Value</p></th><th><p>Meaning</p></th></tr>
</thead><tbody>
 <tr><td><p>0</p></td><td><p>Pending. Client MUST continue polling.</p></td></tr>
 <tr><td><p>1</p></td><td><p>Denied / failed. Client MUST stop polling.</p></td></tr>
 <tr><td><p>2</p></td><td><p>Approved. Client MUST proceed to login completion.</p></td></tr>
</tbody></table>

##### 2.6.1.1.3 Processing Details

Clients SHOULD poll at intervals of several seconds until approval, denial,
a finite local deadline, or cancellation. State `0` means pending only while
those bounds permit another poll. Any state other than `0`, `1`, or `2` is
unrecognized: stop and report it; do not interpret it as approval. Transport
errors and malformed responses are not pending states. Bound transport-error
retries separately, considering `iMaxPollErrors` when supplied, and do not
restart the challenge automatically. No browser execution is required.

For example, DeviceCodeStatus may be polled about every five seconds.
Auth Config may advertise `iPollingTimeout`, `iMaxPollErrors`, and
`iRemoteNgcPollingType`; do not infer undocumented units from example values
or apply SAS polling units to this page (§2.23).

<a id="27-login-passwordless-remote-ngc-completion"></a>

## 2.7 Login (Passwordless Remote NGC Completion)

### 2.7.1 login

#### 2.7.1.1 POST

This method is transported by an HTTP POST to `$Config.urlPost` from the
ConvergedSignIn Auth Config (tenant login endpoint).

##### 2.7.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/{tenant}/login
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>code</p></td><td><p>Remote NGC SessionIdentifier</p></td></tr>
 <tr><td><p>psRNGCSLK</p></td><td><p>Same SessionIdentifier</p></td></tr>
 <tr><td><p>login</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>loginfmt</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>psRNGCEntropy</p></td><td><p>Entropy integer as decimal string</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current flow token</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current canary</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Current sCtx</p></td></tr>
</tbody></table>

<a id="27112-response-body"></a>

##### 2.7.1.1.2 Response Body

On success ESTS returns `302` with a `Location` header of the form:

<pre><code>{redirect_uri}?code={authorization_code}&amp;session_state={guid}
</code></pre>

The `redirect_uri` matches the authorize request (for example
`ms-aadj-redir://auth/drs`).

Retain applicable cookies from the response. The form uses the entry page's
`flowToken`, `ctx`, and `canary`, together with GetOneTimeCode's identifier
and entropy (§2.3.4). Neither a fixed cookie inventory nor trace headers are
prerequisites for recognizing an authorization response.

##### 2.7.1.1.3 Processing Details

Extract the authorization response using §2.22 and hand it to the upstream
protocol (§2.12). Other wrappers and interrupts use the same dispatcher. No HTML
rendering is required.

<a id="28-login-password-submission"></a>

## 2.8 Login (Password Submission)

### 2.8.1 login

#### 2.8.1.1 POST

This method is transported by an HTTP POST to `$Config.urlPost` from
ConvergedSignIn when password authentication is used.

##### 2.8.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/{tenant}/login
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>login</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>passwd</p></td><td><p>Password</p></td></tr>
 <tr><td><p>ctx</p></td><td><p><code>$Config.sCtx</code></p></td></tr>
 <tr><td><p>flowToken</p></td><td><p><code>$Config.sFT</code></p></td></tr>
 <tr><td><p>canary</p></td><td><p><code>$Config.canary</code></p></td></tr>
 <tr><td><p>client_id</p></td><td><p>Application client ID</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>Correlation GUID</p></td></tr>
</tbody></table>

<a id="28112-response-body"></a>

##### 2.8.1.1.2 Response Body

Outcomes:

1. __MFA required__: `200` HTML with `$Config.pgid` = `ConvergedTFA`,
   including `arrUserProofs`, `urlBeginAuth`, `urlEndAuth`, and
   `urlPost` pointing at `/common/SAS/ProcessAuth`.
2. __Authorization code__: `302` to `redirect_uri` with `code` when no additional MFA challenge is
   needed (including an already sufficient session).
3. __Other interrupts__: `200` HTML with `pgid` values such as
   `KmsiInterrupt`, `ConvergedChangePassword`, or `ConvergedConsent`.

ESTS MAY also return intermediate HTML pages that auto-submit a form
(“Working…”, “Click Submit to continue”). Clients MUST parse the form
`action` and continuation inputs, applying §2.18 and §2.22, including
continuation bounds.

##### 2.8.1.1.3 Processing Details

After a ConvergedTFA response, the client MUST parse the new `$Config` and
select a supported method from `arrUserProofs`. SAS methods use BeginAuth /
EndAuth; FidoKey and AccessPass follow [§2.14](#214-fido-authentication) and
[§2.15](#215-temporary-access-pass-completion), respectively. Cookies from this response
(including authentication cookies such as `ESTSAUTH`) MUST be retained. The ConvergedTFA response can carry `ESTSAUTH`,
`ESTSAUTHPERSISTENT`, or `ESTSAUTHLIGHT` before MFA is satisfied
([§2.20](#220-session-cookies-and-response-headers)).

A successful primary-authentication response can supply a new MFA page
with `sessionId`, `sFT`, `sCtx`, `canary`, `arrUserProofs`, and SAS endpoint
URLs. Use that page for the next challenge. Correlation GUIDs and form-field
order are not authentication state. Incorrect-password and account failures
are delivered through Auth Config error fields; do not assume ConvergedTFA
merely because the response is HTML (§2.21).

<a id="29-sas-beginauth"></a>

## 2.9 SAS BeginAuth

### 2.9.1 BeginAuth

#### 2.9.1.1 POST

This method is transported by an HTTP POST to `$Config.urlBeginAuth`.

##### 2.9.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/common/SAS/BeginAuth
Content-Type: application/json; charset=utf-8
canary: {SAS canary}
</code></pre>

Request body:

<pre><code class="lang-json">{
  "AuthMethodId": "PhoneAppNotification",
  "Method": "BeginAuth",
  "ctx": "{sCtx}",
  "flowToken": "{sFT}"
}
</code></pre>

__AuthMethodId__: A SAS method from `arrUserProofs[].authMethodId`.
`FidoKey` and `AccessPass` do not use BeginAuth.

__Method__: MUST be `BeginAuth`.

__SAS canary__: The header named `canary` is sent with the MFA page's
`canary` in one request form and with its `apiCanary` in another. Retain
both values, and use the chosen form consistently for BeginAuth and EndAuth
POST. This does not establish general interchangeability at other endpoints;
ProcessAuth uses the page's `canary` form field. Neither token's name is the
HTTP header name `apiCanary`.

BeginAuth starts the selected challenge; it can deliver a push, SMS, or call.
A failed or lost response does not prove that delivery did not occur. Avoid
automatically starting another push challenge after an uncertain result,
including fallback from Remote NGC to SAS notification.

##### 2.9.1.1.2 Response Body

<pre><code class="lang-json">{
  "Success": true,
  "ResultValue": "Success",
  "Message": null,
  "AuthMethodId": "PhoneAppNotification",
  "ErrCode": 0,
  "Retry": false,
  "FlowToken": "string",
  "Ctx": "string",
  "SessionId": "string",
  "CorrelationId": "string",
  "Timestamp": "2026-11-04T17:48:12Z",
  "Entropy": 98,
  "ReselectUIOption": 0,
  "ContinuationToken": null,
  "MobileAppAuthDetails": null
}
</code></pre>

##### 2.9.1.1.3 Processing Details

On `Success=true`, save `FlowToken`, `Ctx`, and `SessionId` as the SAS
challenge state, retaining the MFA page's state separately. EndAuth uses
one of the patterns in §2.3.4. Display `Entropy` for notification number
matching when applicable; it need not be meaningful in later responses.

SAS `SessionId` and `$Config.sessionId` can differ. `CorrelationId`,
`Timestamp`, `Entropy`, `ReselectUIOption`, `ContinuationToken`, and
`MobileAppAuthDetails` are response metadata when present; they are not
additional completion fields in these exchanges. Do not require equality
between correlation IDs, page IDs, or server trace IDs.

On failure, inspect `ResultValue`, `Message`, and `ErrCode` when present.
Do not proceed to EndAuth as though a challenge had started. A failed method
attempt does not prove all other offered methods are unusable; switching or
restarting is an explicit client/user decision using valid page state.

<a id="210-sas-endauth"></a>

## 2.10 SAS EndAuth

<a id="2101-endauth-poll"></a>

### 2.10.1 EndAuth (poll)

#### 2.10.1.1 GET

This method is transported by an HTTP GET to `$Config.urlEndAuth` for
methods that wait on an out-of-band approval (PhoneAppNotification, voice).

##### 2.10.1.1.1 Request

<pre><code>GET https://login.microsoftonline.com/common/SAS/EndAuth?authMethodId={AuthMethodId}&amp;pollCount={n}
</code></pre>

Request headers:

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>x-ms-sessionId</p></td><td><p>Page <code>sessionId</code> in the retained-state pattern, or SAS response <code>SessionId</code> in the response-state pattern (§2.3.4)</p></td></tr>
 <tr><td><p>x-ms-flowToken</p></td><td><p>BeginAuth token retained across polls, or preceding SAS response token (§2.3.4)</p></td></tr>
 <tr><td><p>x-ms-ctx</p></td><td><p>BeginAuth context retained across polls, or preceding SAS response context (§2.3.4)</p></td></tr>
 <tr><td><p>Cookie</p></td><td><p>ESTS cookies</p></td></tr>
</tbody></table>

`pollCount` is a 1-based counter of poll attempts.

<a id="210112-response-body"></a>

##### 2.10.1.1.2 Response Body

Pending:

<pre><code class="lang-json">{
  "Success": false,
  "ResultValue": "AuthenticationPending",
  "Message": "AuthenticationPending",
  "AuthMethodId": "PhoneAppNotification",
  "ErrCode": 0,
  "Retry": true,
  "FlowToken": "string",
  "Ctx": "string",
  "SessionId": "string",
  "CorrelationId": "string",
  "Timestamp": "string",
  "Entropy": 0,
  "ReselectUIOption": 0,
  "ContinuationToken": null,
  "MobileAppAuthDetails": null
}
</code></pre>

Approved:

<pre><code class="lang-json">{
  "Success": true,
  "ResultValue": "Success",
  "Message": null,
  "AuthMethodId": "PhoneAppNotification",
  "ErrCode": 0,
  "Retry": false,
  "FlowToken": "string",
  "Ctx": "string",
  "SessionId": "string",
  "CorrelationId": "string",
  "Timestamp": "string",
  "Entropy": 0,
  "ReselectUIOption": 0,
  "ContinuationToken": null,
  "MobileAppAuthDetails": {
    "AuthAppState": "base64-opaque",
    "RespondingDeviceSapadId": "guid",
    "PolicyResults": [
      { "Feature": 2, "PolicyEvaluationState": 2,
        "PolicyEvaluationStatusValue": "NumberMatchCorrectNumberEntered",
        "PolicyEvaluationStatus": "numberMatchCorrectNumberEntered",
        "UcpState": 2, "AppState": 0 },
      { "Feature": 1, "PolicyEvaluationState": 2,
        "PolicyEvaluationStatusValue": "unknown",
        "PolicyEvaluationStatus": "unknown", "UcpState": 0, "AppState": 2 },
      { "Feature": 3, "PolicyEvaluationState": 1, "...": "..." },
      { "Feature": 4, "PolicyEvaluationState": 1, "...": "..." }
    ]
  }
}
</code></pre>

`MobileAppAuthDetails`, including opaque app state and policy evaluation
entries, may accompany approval. These details are informational and are
not posted to ProcessAuth. The example's feature numbers and policy strings
are not required response members or a second success predicate.

##### 2.10.1.1.3 Processing Details

If `Success=false` and `Retry=true`, wait `iPollingInterval` milliseconds
before the next poll, incrementing the 1-based `pollCount` and respecting
`iMaxPollAttempts` when advertised. The first poll may follow BeginAuth
without waiting a full interval. Use the chosen state pattern from §2.3.4.

On `Success=true`, retain the returned `FlowToken` and `Ctx` and continue to
ProcessAuth. On `Success=false` and `Retry=false`, stop this polling
challenge; diagnostic fields may explain denial, timeout, or another failure.
A missing `Retry` on an unsuccessful poll is not permission for unbounded
polling. Treat an unrecognized response as a failure requiring explicit
handling. These polling rules do not define code-entry retry behavior.

Stop at the attempt limit, a local deadline, cancellation, or terminal failure.
Use a finite local bound when an advertised limit is absent. Transport errors
are distinct from a pending challenge and do not restart it automatically.
SAS endpoints can also return HTML containing an Auth Config error; classify
the response before assuming JSON (§2.21).

<a id="2102-endauth-otp-submission"></a>

### 2.10.2 EndAuth (OTP submission)

#### 2.10.2.1 POST

For methods that collect a code from the user (PhoneAppOTP, OneWaySMS, and
similar), EndAuth is invoked as HTTP POST with JSON body:

<pre><code class="lang-json">{
  "AdditionalAuthData": "{otp}",
  "AuthMethodId": "{authMethodId}",
  "SessionId": "{sessionId}",
  "FlowToken": "{flowToken}",
  "Ctx": "{ctx}",
  "Method": "EndAuth"
}
</code></pre>

Headers include `Content-Type: application/json; charset=utf-8` and
`canary: {SAS canary}` as defined in §2.9.

`SessionId` is the SAS challenge identifier returned by BeginAuth. `FlowToken`
and `Ctx` initially come from the same response. Keep the original challenge
state separately from failed-submission metadata. The shared SAS response
members are illustrated in §2.10.1.1.2, but code submission has its own
processing rules:

1. Keep the OTP as a string, including leading zeroes. Trim surrounding user
   entry whitespace; do not convert it to an integer.
2. On `Success=true`, use the returned `FlowToken` and `Ctx` for ProcessAuth.
3. An incorrect or expired code can be rejected while the challenge remains
   usable. Such a response may omit `Retry` or carry `Retry=false`; the polling
   rule does not make every code rejection terminal. A recoverable rejection
   permits collecting a replacement code and submitting it with the retained
   challenge state, without starting another BeginAuth.
4. Do not classify every `Message` as a recoverable code rejection. An expired
   flow token, denied challenge, or unrecognized error requires stopping or
   explicit recovery. Failed requests never advance to ProcessAuth. HTML
   service errors and transport failures also need separate handling.
5. Do not repeatedly submit the same rejected code automatically. Bound
   user-driven retries by cancellation and a finite local deadline; no
   universal server retry allowance is established here.

<a id="211-sas-processauth"></a>

## 2.11 SAS ProcessAuth

### 2.11.1 ProcessAuth

#### 2.11.1.1 POST

This method is transported by an HTTP POST to `$Config.urlPost` from the
ConvergedTFA page (typical URL:
`https://login.microsoftonline.com/common/SAS/ProcessAuth`).

##### 2.11.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/common/SAS/ProcessAuth
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>request</p></td><td><p><code>Ctx</code> from the successful EndAuth response</p></td></tr>
 <tr><td><p>mfaAuthMethod</p></td><td><p>Auth method id. <code>ConsolidatedTelephony</code> is posted as
 <code>OneWaySMS</code>.</p></td></tr>
 <tr><td><p>login</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current flow token</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Canary from ConvergedTFA <code>$Config</code></p></td></tr>
</tbody></table>

##### 2.11.1.1.2 Response Body

On success, the response can deliver an authorization response (§2.22),
return an auto-submit interstitial (§2.18), or present an Auth Config
interrupt (§1.3.11), including ProofUp or KMSI. These outcomes use the same
response dispatcher as other completion posts; successful EndAuth alone is
not authorization completion.

When ProofUp advertises `urlSkipMfaRegistration`, the client may use the
resume operation in §2.13. Retain the `request` value submitted to
ProcessAuth because a following ProofUp page can omit `sCtx`.

ProcessAuth may rotate authentication and context cookies. Their presence,
quantity, or issue order is not a success signal (§2.20).

<a id="212-authorization-code-token-exchange"></a>

## 2.12 Authorization Code Handoff (Upstream)

ESTS interaction finishes when the authorization response is delivered (§2.22).
Redeem and validate it using [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
and the applicable Microsoft endpoint contract (§2.2.2). PKCE is specified by
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), and token validation by
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
Token exchange, refresh, claim inventories, and token lifetimes are outside
this ESTS MFA specification.

<a id="213-skip-mfa-registration-resume"></a>

## 2.13 Skip MFA Registration Resume

### 2.13.1 resume

#### 2.13.1.1 POST

When ProcessAuth returns ConvergedProofUpRedirect with
`urlSkipMfaRegistration`, the client MAY continue without completing method
registration.

##### 2.13.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/{tenant}/resume?skipmfaregistration=1
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>flowtoken</p></td><td><p>Flow token from the ProofUp Auth Config (<code>sFT</code>). Note the lowercase
 field name.</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>The <code>request</code> value posted to ProcessAuth; the ProofUp page has no <code>sCtx</code>.</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Canary from the ProofUp Auth Config</p></td></tr>
</tbody></table>

##### 2.13.1.1.2 Response Body

A successful skip can return `302` with `code` and `session_state`.
Handle other authorization wrappers, interrupts, or continuation pages
through §2.22. Persist returned cookie updates.

In the skip-resume pattern above, ProofUp lacks `sCtx`, so `ctx` reuses
ProcessAuth's submitted `request`. The page's `urlPost` can point to a
separate registration host; it is not the skip endpoint. Use the advertised
`urlSkipMfaRegistration`, preserving its query, rather than deriving it from
`urlPost`.

A skip URL can be offered with `sErrorCode=50203` and without
`iRemainingDaysToSkipMfaRegistration`. Absence of remaining-days metadata
does not invalidate an offered skip. This differs from postponement (§2.16);
without an offered continuation, registration requires external interaction.

<a id="214-fido-authentication"></a>

## 2.14 FIDO Authentication

FIDO may be offered passwordlessly (via GetCredentialType `FidoParams`) or
after password login (via ConvergedTFA `arrUserProofs` entry `FidoKey` /
`arrFidoAllowList`). Both use the same ESTS HTTP surface: a challenge
bootstrap POST to `urlFidoLogin`, then an assertion POST to the initiating page's `urlPost`.

<a id="2141-fidologin-challenge-bootstrap"></a>

### 2.14.1 FidoLogin Challenge Bootstrap

#### 2.14.1.1 POST

##### 2.14.1.1.1 Request

<pre><code>POST {urlFidoLogin}
Content-Type: application/x-www-form-urlencoded
</code></pre>

Typical `urlFidoLogin` shape:
`https://login.microsoft.com/{tenant}/fido/get?uiflavor=Host`

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>flow</p></td><td><p><code>mfa</code></p></td></tr>
 <tr><td><p>allowedIdentities</p></td><td><p><code>$Config.iAllowedIdentities</code> as decimal string</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current flow token (<code>sFT</code>)</p></td></tr>
 <tr><td><p>serverChallenge</p></td><td><p>Current flow token (<code>sFT</code>)</p></td></tr>
 <tr><td><p>postBackUrl</p></td><td><p>Current <code>urlPost</code></p></td></tr>
 <tr><td><p>postBackUrlAad</p></td><td><p>Current <code>urlPost</code></p></td></tr>
 <tr><td><p>cancelUrl</p></td><td><p>Current <code>urlResume</code></p></td></tr>
 <tr><td><p>resumeUrl</p></td><td><p>Current <code>urlResume</code></p></td></tr>
 <tr><td><p>correlationId</p></td><td><p>Client request / correlation GUID</p></td></tr>
 <tr><td><p>credentialsJson</p></td><td><p>A serialized entry of the FIDO allow-list
 (<code>FidoParams.AllowList[0]</code> or <code>arrFidoAllowList[0]</code> in this request pattern). Pass the string unchanged, without serializing the string as JSON again</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Current <code>sCtx</code></p></td></tr>
 <tr><td><p>username</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>loginCanary</p></td><td><p><code>$Config.canary</code></p></td></tr>
</tbody></table>

##### 2.14.1.1.2 Response Body

`200` HTML containing a new Auth Config. Take the following completion
values from this response:

- `sFidoChallenge` — challenge material for the local authenticator
- `sCrossDomainCanary` — posted later as `lmcCanary`
- `sessionId` — posted later as `hpgrequestid`

Retain the initiating ConvergedSignIn or ConvergedTFA page's `urlPost`,
`sFT`, `sCtx`, and `canary`. The assertion request uses those retained
values, not a blanket replacement by the bootstrap page's state. This applies
to both passwordless FIDO and FidoKey selected after primary authentication.
The allow-list used for bootstrap belongs to the initiating flow.

<a id="214113-processing-details"></a>

##### 2.14.1.1.3 Processing Details

The bootstrap POST is sent to a different host (`login.microsoft.com`) than
the remainder of the flow (`login.microsoftonline.com`) named by the Auth Config.
The request is sent with a browser `User-Agent` string; ESTS only
offers FIDO to user agents it recognizes as FIDO-capable; the Auth Config
reports its parse of the user agent in `$Config.browser`
([§2.3.1](#231-common-fields)). A client SHOULD send the same string on authorize and
GetCredentialType. The `sFidoChallenge` value present on the
initial ConvergedSignIn page begins `O.` followed by a JWT whose
`aud` is `urn:microsoft:fido:challenge`.

`FidoParams.HasCrossDeviceCapablePasskey` (or
`$Config.fIsPasskeySupportEnabled`) can advertise cross-device passkey
capabilities or UI support. Neither establishes possession of a physical key
or client support for the offered mechanism. Local authenticator selection
is outside this HTTP protocol; the ESTS request pattern is unchanged.

<a id="2142-fido-assertion-completion"></a>

### 2.14.2 FIDO Assertion Completion

#### 2.14.2.1 POST

##### 2.14.2.1.1 Request

<pre><code>POST {initiating-page urlPost}
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>type</p></td><td><p><code>23</code></p></td></tr>
 <tr><td><p>ps</p></td><td><p><code>23</code></p></td></tr>
 <tr><td><p>assertion</p></td><td><p>Serialized FIDO/WebAuthn assertion payload, carried as one form value; do not concatenate unescaped JSON into the form body</p></td></tr>
 <tr><td><p>lmcCanary</p></td><td><p><code>sCrossDomainCanary</code> from the FIDO Auth Config</p></td></tr>
 <tr><td><p>hpgrequestid</p></td><td><p>Bootstrap response <code>sessionId</code></p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Initiating page <code>sCtx</code></p></td></tr>
 <tr><td><p>canary</p></td><td><p>Initiating page <code>canary</code></p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Initiating page <code>sFT</code></p></td></tr>
</tbody></table>

##### 2.14.2.1.2 Response Body

Success yields either:

1. `302` `Location` containing `code`, or
2. `200` HTML that includes an anchor whose `href` carries `code` (or
   `error` with an optional `error_description`) as query parameters. Clients MUST parse that `href`
   when `Location` is absent.

The response can also contain an interrupt or `pgid=ConvergedTFA` requiring
another offered proof. Dispatch the result using §2.22 and §1.3.11; FIDO
completion does not guarantee satisfaction of every tenant policy.
Intermediate auto-submit HTML may appear (§2.18).

Local authenticator operations follow
[Web Authentication](https://www.w3.org/TR/webauthn-3/). This specification
does not redefine authenticator processing or establish an additional JSON
assertion schema. Form-encode the complete assertion string and all opaque
values so characters such as `+`, `=`, braces, and quotes are preserved.

<a id="215-temporary-access-pass-completion"></a>

## 2.15 Temporary Access Pass Completion

### 2.15.1 Access Pass POST

#### 2.15.1.1 POST

Used for passwordless Access Pass (GetCredentialType) and for
`arrUserProofs` method `AccessPass` after password login. BeginAuth is not
invoked.

##### 2.15.1.1.1 Request

<pre><code>POST {urlPost}
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>login</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>loginfmt</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>accesspass</p></td><td><p>Temporary Access Pass string</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current canary</p></td></tr>
 <tr><td><p>hpgrequestid</p></td><td><p>Current sessionId</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current flow token</p></td></tr>
 <tr><td><p>ctx</p> or <p>request</p></td>
 <td><p>Current ctx. Use form field name <code>request</code> when <code>urlPost</code> contains
 <code>ProcessAuth</code>; otherwise use <code>ctx</code>.</p></td></tr>
</tbody></table>

##### 2.15.1.1.2 Response Body

Same completion shapes as password login / ProcessAuth: `302` with `code`,
Auth Config interrupt, or auto-submit HTML.

<a id="216-kmsi-and-proofup-continue-posts"></a>

## 2.16 KMSI and ProofUp Continue Posts

### 2.16.1 LoginOptions Continue

#### 2.16.1.1 POST

When Auth Config `pgid` is `KmsiInterrupt`, or when
`ConvergedProofUpRedirect` is returned with remaining days allowed to postpone
MFA registration, ESTS accepts a continue POST to the current `urlPost`.

##### 2.16.1.1.1 Request

<pre><code>POST {urlPost}
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>LoginOptions</p></td><td><p><code>1</code></p></td></tr>
 <tr><td><p>ctx</p></td><td><p>KMSI: interrupt page's <code>sCtx</code>. ProofUp: preceding Auth Config's <code>sCtx</code>, as specified below.</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>KMSI: interrupt page's <code>sFT</code>. ProofUp: preceding Auth Config's <code>sFT</code>, as specified below.</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current canary</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>Correlation GUID</p></td></tr>
</tbody></table>

Token selection differs by interrupt: when advancing
ConvergedProofUpRedirect with remaining skip days, the post carries the `ctx`
and `flowToken` of the Auth Config that preceded the interrupt together with
the interrupt page's `canary`; for KMSI the post carries the interrupt page's
own `sFT`. Whether ESTS would also accept the other token choice is
unspecified.

##### 2.16.1.1.2 Response Body

A new Auth Config HTML page, a `302` with `code`, or further interrupts.
Clients MUST re-parse `$Config` on `200` HTML.

When `urlSkipMfaRegistration` is advertised, the client MAY use the
skip-resume API in [§2.13](#213-skip-mfa-registration-resume). When that URL is
absent and no postponement is offered, MFA method registration must be
completed out of band.

<a id="217-password-change-sspr"></a>

## 2.17 Password Change (SSPR)

### 2.17.1 Overview

`pgid=ConvergedChangePassword` Auth Config advertises:

- `urlAsyncSsprBegin`
- `urlAsyncSsprPoll`
- `urlPost` for final confirmation

### 2.17.2 SSPR Begin

#### 2.17.2.1 POST

<pre><code>POST {urlAsyncSsprBegin}
Content-Type: application/json
</code></pre>

<pre><code class="lang-json">{
  "Ctx": "{sCtx}",
  "FlowToken": "{sFT}",
  "OldPassword": "{current-password}",
  "NewPassword": "{new-password}"
}
</code></pre>

Response JSON includes at least:

<pre><code class="lang-json">{
  "IsJobPending": true,
  "Ctx": "string",
  "FlowToken": "string",
  "CoupledDataCenter": "string",
  "CoupledScaleUnit": "string",
  "ErrorMessage": null
}
</code></pre>

### 2.17.3 SSPR Poll

#### 2.17.3.1 POST

While `IsJobPending` is true:

<pre><code>POST {urlAsyncSsprPoll}
Content-Type: application/json
</code></pre>

<pre><code class="lang-json">{
  "Ctx": "{Ctx}",
  "FlowToken": "{FlowToken}",
  "CoupledDataCenter": "{CoupledDataCenter}",
  "CoupledScaleUnit": "{CoupledScaleUnit}"
}
</code></pre>

A non-null `ErrorMessage` indicates failure. When `IsJobPending` becomes
false without error, proceed to final confirmation.

### 2.17.4 SSPR Final Confirmation

#### 2.17.4.1 POST

<pre><code>POST {urlPost}
Content-Type: application/json
</code></pre>

<pre><code class="lang-json">{
  "Ctx": "{Ctx}",
  "FlowToken": "{FlowToken}",
  "currentpasswd": "{current-password}",
  "confirmnewpasswd": "{new-password}",
  "canary": "{canary}"
}
</code></pre>

An alternative final-confirmation request uses
`Content-Type: application/x-www-form-urlencoded` with lowercase `ctx` and
`flowToken`, plus `currentpasswd`, `confirmnewpasswd`, and the page's
`canary`. In both variants, take the context and flow token from the completed
job response. Keep casing and encoding matched to the selected request form.

An HTTP success status can acknowledge the JSON confirmation. When a response
contains a page or authorization response, dispatch it normally rather than
assuming every HTTP 200 completes authentication. Restarting sign-in with the
new password is a client recovery approach when continuation is unavailable;
omitting `amr_values` on a restarted request is not an ESTS requirement.

Resolve relative job and confirmation URLs against the page that advertised
them (§2.22). Polling at about one-second intervals is an example cadence;
apply a finite deadline and cancellation. Only confirm after the job completes
without `ErrorMessage`. An error may require correcting the proposed password
and beginning a new job, not confirming the failed job.

<a id="218-intermediate-auto-submit-html"></a>

## 2.18 Intermediate Auto-Submit HTML

ESTS intermittently returns `200` HTML pages whose body instructs the user
agent to continue (for example text containing “Working…”, “Click Submit to
continue”, “Click here to finish the authorization process”, or a form with
`<input type="submit">`).

Processing rules:

1. Parse the first HTML `form`.
2. Read the form `action` and resolve a relative value against the response
   document's URL to obtain the next POST URL.
3. Collect enabled continuation `input` elements that have both `name` and
   `value`, excluding unchecked checkboxes/radio buttons and unactivated
   submit controls. Preserve repeated field names and their order.
4. `POST` `application/x-www-form-urlencoded` to the action URL with those
   fields.
5. Dispatch each response using §2.22. Continue only while another genuine
   continuation form is present; stop at an authorization response, interrupt,
   error, cancellation, or a finite local hop/deadline limit. A repeated form
   is not permission to submit indefinitely.

Clients MUST NOT require a full browser layout engine; HTML form parsing is
sufficient.

Interstitials are detected by a substring match on the response body for
any of `Click Submit to continue`, `Working...`,
`Click here to finish the authorization process`, or `<input type="submit"`.
These markers describe observed pages and are only detection hints; confirm
that a continuation form is present before submitting it. They are not
reliable for every locale or HTML serialization. An ordinary submit button
alone does not establish that a page is an interstitial.
For the observed continuation forms, only inputs carrying both `name` and
`value` attributes are posted; exclude disabled controls, unchecked
checkboxes/radio buttons, and unactivated submit controls. Preserve repeated
field names and their order. The form
is posted without any ESTS-specific headers.

<a id="219-oauth-20-device-authorization-grant"></a>

## 2.19 Device Authorization Grant (Upstream)

The device authorization grant is a separate OAuth flow. It is specified by
[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628), with Microsoft endpoint
behavior in [Microsoft's device-flow documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code).
It is an optional alternative when application registration and tenant policy
permit it; it does not bypass registration, consent, or authentication-strength
requirements.

<a id="2191-organizational-device-code"></a>
<a id="2192-consumers-personal-account-device-code"></a>
<a id="2192-consumers-device-code"></a>

Organizational and personal-account routing belongs to that upstream flow.
The Remote NGC `GetOneTimeCode` / `DeviceCodeStatus` exchanges (§2.5–§2.7)
are ESTS authentication operations and MUST NOT be treated as RFC 8628
requests or polled using its token-endpoint rules.

<a id="220-session-cookies-and-response-headers"></a>

## 2.20 Session Cookies and Response Headers

### 2.20.1 Cookies

Maintain applicable cookies across the interaction, honoring response
attributes according to [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265).
ESTS cookie names encountered in these exchanges include:

<table class="protocol-table"><thead>
<tr><th><p>Cookies</p></th><th><p>ESTS role</p></th></tr>
</thead><tbody>
<tr><td><p><code>buid</code>, <code>esctx</code>, <code>esctx-{id}</code></p></td><td><p>Browser/page context. Context-cookie names and values can change between pages; apply updates and deletions.</p></td></tr>
<tr><td><p><code>fpc</code></p></td><td><p>Session/browser tracking; may be updated across requests.</p></td></tr>
<tr><td><p><code>x-ms-gateway-slice</code>, <code>stsservicecookie</code></p></td><td><p>Routing hints; not substitutes for opaque flow state.</p></td></tr>
<tr><td><p><code>ESTSAUTH</code>, <code>ESTSAUTHPERSISTENT</code>, <code>ESTSAUTHLIGHT</code></p></td><td><p>Authentication-related state; can be issued before MFA is satisfied and rotated by completion posts.</p></td></tr>
<tr><td><p><code>CCState</code>, <code>SignInStateCookie</code></p></td><td><p>Additional sign-in state that can accompany authorization completion.</p></td></tr>
</tbody></table>
The inventory is descriptive: neither all names nor a fixed issue order is
required for every flow. Cookie names, GUID relationships, and expiry durations
do not establish authentication success. ESTS cookies scoped to
`login.microsoftonline.com` are not sent to `login.microsoft.com` or an external IdP.

### 2.20.2 Request Headers

<table class="protocol-table"><thead>
<tr><th><p>Header</p></th><th><p>ESTS use</p></th></tr>
</thead><tbody>
<tr><td><p><code>Content-Type</code></p></td><td><p>JSON for discovery, Remote NGC status, SAS BeginAuth/EndAuth POST, and SSPR jobs; form encoding for credential and completion posts. SSPR confirmation has both variants (§2.17).</p></td></tr>
<tr><td><p><code>client-request-id</code></p></td><td><p>Correlation GUID on GetCredentialType and GetOneTimeCode; not an authentication credential.</p></td></tr>
<tr><td><p><code>canary</code></p></td><td><p>Entry-page <code>canary</code> on GetOneTimeCode/DeviceCodeStatus. SAS BeginAuth and EndAuth POST have the canary-header variants in §2.9.</p></td></tr>
<tr><td><p><code>x-ms-sessionId</code>, <code>x-ms-flowToken</code>, <code>x-ms-ctx</code></p></td><td><p>EndAuth GET state from one consistent polling pattern (§2.3.4).</p></td></tr>
<tr><td><p><code>User-Agent</code></p></td><td><p>A browser string can affect advertised credentials, especially FIDO. Use a consistent FIDO-capable browser string for authorize, discovery, and bootstrap; later SAS requests can accept a product token.</p></td></tr>
</tbody></table>
### 2.20.3 Response Headers

`Set-Cookie` updates the cookie jar; `Location` can carry an authorization
response (§2.22). `client-request-id`, `x-ms-request-id`, `x-ms-ests-server`,
and `x-ms-clientdata` provide correlation or service metadata when present.
Do not derive a state field from diagnostic headers when it is explicitly
supplied by the protocol. Polls can be served by different nodes; retain
tokens and cookies rather than depending on node affinity. Cache and
script-policy headers are not additional MFA request parameters.

<p style="text-align:center"><a href="images/fig-21-cookies.png"><img src="images/fig-21-cookies.png" alt="Figure 21: Cookie handling before and after MFA completion." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 21</b>: Cookie handling before and after MFA completion.</p>

<a id="221-error-signaling"></a>

## 2.21 Error Signaling

Classify responses by the current endpoint and content; HTTP 200 alone does
not indicate successful authentication. ESTS-specific error channels include:

<table class="protocol-table"><thead>
<tr><th><p>Channel</p></th><th><p>Interpretation</p></th></tr>
</thead><tbody>
<tr><td><p>HTML Auth Config</p></td><td><p><code>sErrorCode</code> can be a numeric string or symbolic identifier such as <code>InvalidAccessPass</code>; <code>iErrorCode</code> is numeric. <code>sErrTxt</code>, <code>strServiceExceptionMessage</code>, and <code>arrValErrs</code> may provide diagnostics.</p></td></tr>
<tr><td><p>SAS JSON</p></td><td><p>Check <code>Success</code>; use <code>Retry</code> for polling (§2.10.1), and the separate code-submission rules (§2.10.2). <code>ResultValue</code>, <code>Message</code>, and <code>ErrCode</code> may explain failure.</p></td></tr>
<tr><td><p>Remote NGC JSON</p></td><td><p><code>AuthorizationState</code> determines pending, denial, or approval (§2.6); GetOneTimeCode may instead return an <code>error.message</code> object.</p></td></tr>
<tr><td><p>Authorization response</p></td><td><p>Extract the response using §2.22 and apply upstream OAuth error handling. An <code>error</code> is a failure even if its description is absent.</p></td></tr>
</tbody></table>

An initial ConvergedSignIn page can carry `50058` to indicate no existing
session; it does not prevent starting sign-in. A ProofUp page can carry
`50203` while offering a valid skip route. Interpret page identifiers and
advertised actions before declaring such an interrupt terminal. Conversely,
a recognizable `pgid` does not suppress a credential or service error.

A code rejection can leave a challenge usable; a denied polling challenge or
expired flow state cannot be treated as mere pending approval. The latter
requires stopping or an explicit new interaction, not silently replaying a
failed operation. SAS endpoints may return HTML service errors instead of
JSON, so check for an Auth Config error before reporting a JSON parse failure.

For AADSTS meanings and standard OAuth error responses, use
[Microsoft's error reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes).
Numeric catalog entries and localized text are diagnostics, not a universal
recovery decision table. Registration, consent, or Conditional Access can
require interaction beyond these MFA APIs; an alternative grant does not
bypass those requirements.

<p style="text-align:center"><a href="images/fig-22-errors.png"><img src="images/fig-22-errors.png" alt="Figure 22: ESTS error channels and endpoint-specific recovery." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 22</b>: ESTS error channels and endpoint-specific recovery.</p>

<a id="222-authorization-response-delivery-forms"></a>

## 2.22 Authorization Response Delivery Forms

An authorization code is delivered in one of four forms. A client MUST accept
all of them after every POST that can complete the flow (password `login`,
Remote NGC `login`, ProcessAuth, `resume`, FIDO assertion, Access Pass,
`LoginOptions=1`) and after a silent authorize request:

<table class="protocol-table"><thead>
  <tr><th><p>Form</p></th><th><p>Detection</p></th><th><p>Extraction</p></th></tr>
</thead><tbody>
 <tr><td><p>302 Location</p></td><td><p>HTTP <code>302</code> with <code>Location</code></p></td><td><p>Parse the URL; read <code>code</code> (and <code>session_state</code>). If <code>error</code> is present, treat the response as an error even when <code>error_description</code> is absent (<a href="#221-error-signaling">§2.21</a>). The scheme may be custom (<code>ms-aadj-redir://</code>, <code>companyportal://</code>).</p></td></tr>
 <tr><td><p>302 with HTML anchor</p></td><td><p><code>302</code> whose body is an HTML page with an <code>&lt;a href="..."&gt;</code></p></td><td><p>Read the first anchor's <code>href</code> with an HTML parser, resolve the URL, then decode individual query values once. Do not percent-decode the entire URL before parsing.</p></td></tr>
 <tr><td><p>200 JavaScript redirect</p></td><td><p><code>200</code> HTML containing <code>document.location.replace("{url}")</code></p></td><td><p>Decode JavaScript string escapes without executing the script, parse the URL, and read <code>code</code> or <code>error</code>.</p></td></tr>
 <tr><td><p>200 with FIDO anchor</p></td><td><p><code>200</code> HTML from the FIDO assertion post</p></td><td><p>Read the anchor's <code>href</code> with an HTML parser, parse its URL, and read <code>code</code> or <code>error</code>.</p></td></tr>
</tbody></table>

If none of the forms matches, check for an auto-submit interstitial
([§2.18](#218-intermediate-auto-submit-html)), then parse any `$Config`: an
error, `ConvergedChangePassword`, `ConvergedConsent`, `KmsiInterrupt` (a `200`
with no redirect), `ConvergedProofUpRedirect`, or `ConvergedTFA` requires
handling the new page state (§1.3.11).

Auth Config URLs (`urlPost`, `urlAsyncSsprBegin`, ...) MAY be root-relative.
Resolve relative URLs against the URL of the response that supplied them.
A root-relative path replaces the path while preserving the scheme and
authority. In the SSPR examples, that authority matches the authorize URL;
it can differ after a cross-host response. Values are typically absolute.

<p style="text-align:center"><a href="images/fig-23-authz-response.png"><img src="images/fig-23-authz-response.png" alt="Figure 23: ESTS authorization-response delivery wrappers and upstream handoff." style="max-width:100%"/></a></p>
<p style="text-align:center"><b>Figure 23</b>: ESTS authorization-response delivery wrappers and upstream handoff.</p>

## 2.23 Polling and Continuation Bounds

SAS `iPollingInterval` is expressed in milliseconds and `iMaxPollAttempts`
bounds polling attempts (§2.10.1). Values such as 5000 and 10 are examples,
not constants for all tenants. Remote NGC polling uses its own response
states and local bounds (§2.6); do not interpret an initial page's interval
as SAS milliseconds without an established unit for that field.

Use finite deadlines for polling, code entry, SSPR jobs, and continuation
chains. Stopping locally is not evidence that a server challenge was revoked.
Do not silently start a new challenge after cancellation or timeout. Cookie
expiry is determined by the response attributes, not a fixed lifetime table.

# 3 Protocol Examples (Non-Normative)

Examples below omit cookie headers and truncate opaque tokens.

## 3.1 Passwordless Remote NGC

### 3.1.1 Authority Selection

Select the intended tenant/cloud authority using the external guidance in
§2.1, then enter the ESTS page interaction below.

### 3.1.2 Authorize (Auth Config scrape)

#### Request

<pre><code>GET /{tenant}/oauth2/authorize?client_id=...&amp;response_type=code&amp;redirect_uri=ms-aadj-redir%3A%2F%2Fauth%2Fdrs&amp;prompt=login&amp;scope=openid+profile+&amp;response_mode=query&amp;sso_reload=True&amp;resource=https%3A%2F%2Fenrollment.manage.microsoft.com%2F HTTP/1.1
Host: login.microsoftonline.com
</code></pre>

#### Response (excerpt)

<pre><code>HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: ...

&lt;script type="text/javascript" nonce='...'&gt;//&lt;![CDATA[
$Config={"pgid":"ConvergedSignIn",
 "urlGetCredentialType":"https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
 "urlGetOneTimeCode":"https://login.microsoftonline.com/common/GetOneTimeCode",
 "urlSessionState":"https://login.microsoftonline.com/common/DeviceCodeStatus",
 "urlPost":"https://login.microsoftonline.com/{tenant}/login",
 "sFT":"...","sCtx":"...","canary":"...","sessionId":"...", ...};
//]]&gt;&lt;/script&gt;
</code></pre>

### 3.1.3 GetCredentialType → GetOneTimeCode → DeviceCodeStatus → login

After GetCredentialType returns `HasRemoteNGC` / `RemoteNgcParams`, the client
posts GetOneTimeCode, polls DeviceCodeStatus until `AuthorizationState=2`,
then posts login with `code`, `psRNGCSLK`, `psRNGCEntropy`, `login`,
`loginfmt`, `flowToken`, `canary`, and `ctx`. ESTS responds:

<pre><code>HTTP/1.1 302 Found
Location: ms-aadj-redir://auth/drs?code=1.AWEB...&amp;session_state=...
</code></pre>

## 3.2 Password then PhoneAppNotification

### 3.2.1 Password login → ConvergedTFA Auth Config

#### Request

<pre><code>POST /{tenant}/login HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

login=user%40contoso.com&amp;passwd=...&amp;ctx=...&amp;flowToken=...&amp;canary=...&amp;client_id=...&amp;client-request-id=...
</code></pre>

#### Response (Auth Config excerpt)

<pre><code>$Config={
  "pgid":"ConvergedTFA",
  "urlBeginAuth":"https://login.microsoftonline.com/common/SAS/BeginAuth",
  "urlEndAuth":"https://login.microsoftonline.com/common/SAS/EndAuth",
  "urlPost":"https://login.microsoftonline.com/common/SAS/ProcessAuth",
  "arrUserProofs":[
    {"authMethodId":"PhoneAppNotification","isDefault":true,"display":"","data":"PhoneAppNotification"},
    {"authMethodId":"PhoneAppOTP","isDefault":false,"display":"",
     "phoneAppOtpTypes":["MicrosoftAuthenticatorBasedTOTP"]}
  ],
  "iMaxPollAttempts":10,
  "iPollingInterval":5000,
  "sFT":"...","sCtx":"...","canary":"...","sessionId":"..."
};
</code></pre>

### 3.2.2 BeginAuth

#### Request

<pre><code>POST /common/SAS/BeginAuth HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/json; charset=utf-8
canary: ...

{"AuthMethodId":"PhoneAppNotification","Method":"BeginAuth","ctx":"...","flowToken":"..."}
</code></pre>

#### Response

<pre><code>{"Success":true,"ResultValue":"Success","AuthMethodId":"PhoneAppNotification",
 "FlowToken":"...","Ctx":"...","SessionId":"...","Entropy":98,"Retry":false,"ErrCode":0,...}
</code></pre>

### 3.2.3 EndAuth poll → ProcessAuth → authorization response

These two GET examples illustrate the alternative polling-state patterns
(§2.3.4). They are alternatives for a challenge, not requests to send in
parallel. Header placeholders denote the original opaque values.

Retained-state pattern:

<pre><code>GET {urlEndAuth}?authMethodId=PhoneAppNotification&amp;pollCount=1
x-ms-sessionId: {MFA-page sessionId}
x-ms-flowToken: {BeginAuth FlowToken}
x-ms-ctx: {BeginAuth Ctx}
</code></pre>

Keep these header values on pending polls. In the response-state pattern,
the first poll uses BeginAuth's SAS state and later polls use the preceding
EndAuth response's state:

<pre><code>GET {urlEndAuth}?authMethodId=PhoneAppNotification&amp;pollCount={n}
x-ms-sessionId: {preceding SAS SessionId}
x-ms-flowToken: {preceding SAS FlowToken}
x-ms-ctx: {preceding SAS Ctx}
</code></pre>

Pending polls return `"Success":false,"Retry":true,"ResultValue":"AuthenticationPending"`.
The approving poll returns `"Success":true`. ProcessAuth is then posted:

<pre><code>request=...&amp;mfaAuthMethod=PhoneAppNotification&amp;login=user%40contoso.com&amp;flowToken=...&amp;canary=...
</code></pre>

If a ProofUp interrupt is returned, POST
`/{tenant}/resume?skipmfaregistration=1` with `flowtoken`, `ctx`, and
`canary`. Use this skip only when advertised. The final authorization response
hands control back to the upstream OAuth protocol (§2.12).

## 3.3 SAS PhoneAppOTP

After ConvergedTFA and BeginAuth with `AuthMethodId=PhoneAppOTP`:

<pre><code>POST /common/SAS/EndAuth HTTP/1.1
Content-Type: application/json; charset=utf-8
canary: ...

{"AdditionalAuthData":"123456","AuthMethodId":"PhoneAppOTP",
 "SessionId":"...","FlowToken":"...","Ctx":"...","Method":"EndAuth"}
</code></pre>

Only after `Success=true`, post ProcessAuth with
`mfaAuthMethod=PhoneAppOTP` and the successful response's context/token.
On a recoverable code rejection, re-prompt within the same challenge as
specified in §2.10.2; `Retry=false` or an absent `Retry` is not by itself a
terminal code-entry result.

## 3.4 SAS ConsolidatedTelephony → ProcessAuth mapping

BeginAuth / EndAuth use `AuthMethodId=ConsolidatedTelephony`. ProcessAuth
posts `mfaAuthMethod=OneWaySMS`.

## 3.5 FIDO Assertion Completion

After `urlFidoLogin`, use bootstrap `sCrossDomainCanary` / `sessionId`
and retain initiating `urlPost` / `sCtx` / `canary` / `sFT` (§2.14):

<pre><code>POST {urlPost} HTTP/1.1
Content-Type: application/x-www-form-urlencoded

type=23&amp;ps=23&amp;assertion=...&amp;lmcCanary=...&amp;hpgrequestid=...&amp;ctx=...&amp;canary=...&amp;flowToken=...
</code></pre>

## 3.6 Temporary Access Pass

<pre><code>POST {urlPost} HTTP/1.1
Content-Type: application/x-www-form-urlencoded

login=user%40contoso.com&amp;loginfmt=user%40contoso.com&amp;accesspass=...&amp;canary=...&amp;hpgrequestid=...&amp;flowToken=...&amp;ctx=...
</code></pre>

When `urlPost` is ProcessAuth, replace `ctx=` with `request=`.

## 3.7 External OAuth Flows

Device authorization and token exchange examples belong to the upstream
references in §2.19 and §2.12.

# 4 Security Considerations

Upstream OAuth security and response validation are specified by
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), and
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
Those requirements also apply at the handoff boundaries of this document.
The following considerations concern ESTS interaction itself:

1. Protect passwords, OTPs, tokens, canaries, and session cookies. Use TLS
   and redact secrets from bodies, URLs, headers, and logs, including
   EndAuth's `x-ms-flowToken` and `x-ms-ctx` headers.
2. Parse Auth Config as control data, without executing its scripts. Retain
   state by provenance (§2.3.4), including the FIDO host transition.
3. Maintain applicable cookies across the interaction, including federation
   return. Cookie behavior follows [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265);
   do not forward ESTS cookies to an unrelated IdP or the FIDO host merely
   because those hosts participate in the same flow.
4. `ESTSAUTH*` cookies can be issued before MFA completion. Neither their
   presence nor successful EndAuth establishes completed authorization.
5. Distinguish actual continuation forms from ordinary sign-in, registration,
   or consent forms. Use advertised destinations and respect protocol
   boundaries; do not forward credentials into a guessed continuation.
6. Bound retries and continuation chains. Challenge-start requests can
   deliver notifications even when their response is lost; automatic restart
   can cause duplicate prompts. Respect cancellation and terminal denial.

# 5 Appendix: Endpoint Index

<table class="protocol-table"><thead>
  <tr><th><p>Endpoint</p></th><th><p>Section</p></th></tr>
</thead><tbody>
 <tr><td><p>POST {authority-origin}/login.srf (federated return)</p></td><td><p>1.3.12</p></td></tr>
 <tr><td><p>GET login.microsoftonline.com/{tenant}/oauth2/authorize</p></td><td><p>2.2</p></td></tr>
 <tr><td><p>Auth Config <code>$Config</code> embedded in HTML</p></td><td><p>2.3</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/GetCredentialType</p></td><td><p>2.4</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/GetOneTimeCode</p></td><td><p>2.5</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/DeviceCodeStatus</p></td><td><p>2.6</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/{tenant}/login</p></td><td><p>2.7, 2.8</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/SAS/BeginAuth</p></td><td><p>2.9</p></td></tr>
 <tr><td><p>GET/POST login.microsoftonline.com/common/SAS/EndAuth</p></td><td><p>2.10</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/SAS/ProcessAuth</p></td><td><p>2.11</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/{tenant}/resume?skipmfaregistration=1</p></td><td><p>2.13</p></td></tr>
 <tr><td><p>POST login.microsoft.com/{tenant}/fido/get (urlFidoLogin)</p></td><td><p>2.14.1</p></td></tr>
 <tr><td><p>POST urlPost with FIDO assertion (type=23)</p></td><td><p>2.14.2</p></td></tr>
 <tr><td><p>POST urlPost with accesspass</p></td><td><p>2.15</p></td></tr>
 <tr><td><p>POST urlPost with LoginOptions=1 (KMSI / ProofUp continue)</p></td><td><p>2.16</p></td></tr>
 <tr><td><p>POST urlAsyncSsprBegin / urlAsyncSsprPoll / urlPost (password change)</p></td><td><p>2.17</p></td></tr>
 <tr><td><p>POST intermediate HTML form actions</p></td><td><p>2.18</p></td></tr>
</tbody></table>

<a id="6-appendix-authentication-path-index"></a>

# 6 Appendix: Authentication Path Index

<table class="protocol-table"><thead>
  <tr><th><p>Path</p></th><th><p>Entry</p></th><th><p>Completion APIs</p></th></tr>
</thead><tbody>
 <tr><td><p>Passwordless Remote NGC</p></td><td><p>GetCredentialType RemoteNgcParams</p></td>
  <td><p>GetOneTimeCode → DeviceCodeStatus → login</p></td></tr>
 <tr><td><p>Passwordless Access Pass</p></td><td><p>GetCredentialType HasAccessPass</p></td>
  <td><p>urlPost + accesspass</p></td></tr>
 <tr><td><p>Passwordless FIDO</p></td><td><p>GetCredentialType FidoParams</p></td>
  <td><p>urlFidoLogin → urlPost assertion</p></td></tr>
 <tr><td><p>Password with no further challenge</p></td><td><p>HasPassword</p></td>
  <td><p>login → 302 code</p></td></tr>
 <tr><td><p>Password + PhoneAppNotification / CompanionApps</p></td><td><p>ConvergedTFA arrUserProofs</p></td>
  <td><p>BeginAuth → EndAuth GET poll → ProcessAuth</p></td></tr>
 <tr><td><p>Password + PhoneAppOTP</p></td><td><p>ConvergedTFA</p></td>
  <td><p>BeginAuth → EndAuth POST OTP → ProcessAuth</p></td></tr>
 <tr><td><p>Password + OneWaySMS</p></td><td><p>ConvergedTFA</p></td>
  <td><p>BeginAuth → EndAuth POST SMS → ProcessAuth</p></td></tr>
 <tr><td><p>Password + ConsolidatedTelephony</p></td><td><p>ConvergedTFA</p></td>
  <td><p>BeginAuth/EndAuth as ConsolidatedTelephony; ProcessAuth as OneWaySMS</p></td></tr>
 <tr><td><p>Password + TwoWayVoice*</p></td><td><p>ConvergedTFA</p></td>
  <td><p>BeginAuth → EndAuth GET poll → ProcessAuth</p></td></tr>
 <tr><td><p>Password + FidoKey</p></td><td><p>ConvergedTFA</p></td>
  <td><p>urlFidoLogin → urlPost assertion</p></td></tr>
 <tr><td><p>Password + AccessPass</p></td><td><p>ConvergedTFA</p></td>
  <td><p>urlPost + accesspass</p></td></tr>
 <tr><td><p>KMSI interrupt</p></td><td><p>pgid=KmsiInterrupt</p></td>
  <td><p>urlPost + LoginOptions=1</p></td></tr>
 <tr><td><p>MFA registration ProofUp</p></td><td><p>pgid=ConvergedProofUpRedirect</p></td>
  <td><p>skip resume and/or LoginOptions=1</p></td></tr>
 <tr><td><p>Password change</p></td><td><p>pgid=ConvergedChangePassword</p></td>
  <td><p>SSPR begin → poll → confirm</p></td></tr>
 <tr><td><p>Consent</p></td><td><p>pgid=ConvergedConsent</p></td>
  <td><p>Terminal (no MFA completion API)</p></td></tr>
 <tr><td><p>Federated IdP</p></td><td><p>FederationRedirectUrl</p></td>
  <td><p>IdP return to <code>/login.srf</code> → response / interrupts / ConvergedTFA</p></td></tr>
</tbody></table>

<a id="7-appendix-figure-index"></a>

# 7 Appendix: Figure Index

Each figure is embedded as a PNG; selecting a figure opens it at full
resolution. Figures are non-normative; the sections listed are normative.

<table class="protocol-table"><thead>
<tr><th>Figure</th><th>Subject</th><th>Sections</th><th>File</th></tr>
</thead><tbody>
<tr><td>Figure 1</td><td>Overview of ESTS interaction and upstream protocol boundaries.</td><td>1.2</td><td><code>images/fig-01-overview.png</code></td></tr>
<tr><td>Figure 2</td><td>Common prefix: authority selection, authorize entry, Auth Config, and credential discovery.</td><td>1.3, 2.2–2.4</td><td><code>images/fig-02-common-prefix.png</code></td></tr>
<tr><td>Figure 3</td><td>Selection among usable offered credentials without a fixed attempt order.</td><td>1.3.1</td><td><code>images/fig-03-path-selection.png</code></td></tr>
<tr><td>Figure 4</td><td>Passwordless Remote NGC challenge, polling, and completion.</td><td>1.3.2, 2.5–2.7</td><td><code>images/fig-04-remote-ngc.png</code></td></tr>
<tr><td>Figure 5</td><td>Primary password authentication and response branches.</td><td>1.3.3, 2.8</td><td><code>images/fig-05-password-branch.png</code></td></tr>
<tr><td>Figure 6</td><td>Temporary Access Pass completion without SAS BeginAuth.</td><td>1.3.4, 2.15</td><td><code>images/fig-06-tap.png</code></td></tr>
<tr><td>Figure 7</td><td>Passwordless FIDO bootstrap and assertion state.</td><td>1.3.5, 2.14</td><td><code>images/fig-07-fido-passwordless.png</code></td></tr>
<tr><td>Figure 8</td><td>Notification MFA with alternative SAS polling-state patterns.</td><td>1.3.6, 2.9–2.11</td><td><code>images/fig-08-sas-notification.png</code></td></tr>
<tr><td>Figure 9</td><td>OTP submission, recoverable code rejection, and completion.</td><td>1.3.7, 2.10.2</td><td><code>images/fig-09-sas-otp.png</code></td></tr>
<tr><td>Figure 10</td><td>SMS and ConsolidatedTelephony method mapping.</td><td>1.3.8, 2.11</td><td><code>images/fig-10-sas-sms.png</code></td></tr>
<tr><td>Figure 11</td><td>Voice challenge and bounded approval polling.</td><td>1.3.9, 2.10.1</td><td><code>images/fig-11-sas-voice.png</code></td></tr>
<tr><td>Figure 12</td><td>FIDO selected from ConvergedTFA, retaining initiating state.</td><td>1.3.10, 2.14</td><td><code>images/fig-12-fido-from-tfa.png</code></td></tr>
<tr><td>Figure 13</td><td>Response dispatch across MFA, interrupts, continuations, and errors.</td><td>1.3.11, 2.22</td><td><code>images/fig-13-interrupts.png</code></td></tr>
<tr><td>Figure 14</td><td>KMSI continuation.</td><td>1.3.11, 2.16</td><td><code>images/fig-14-kmsi.png</code></td></tr>
<tr><td>Figure 15</td><td>ProofUp skip-resume and postponement variants.</td><td>1.3.11, 2.13, 2.16</td><td><code>images/fig-15-proofup.png</code></td></tr>
<tr><td>Figure 16</td><td>Password-change job and alternative confirmation encodings.</td><td>2.17</td><td><code>images/fig-16-sspr.png</code></td></tr>
<tr><td>Figure 17</td><td>Bounded continuation-form handling.</td><td>2.18</td><td><code>images/fig-17-autosubmit.png</code></td></tr>
<tr><td>Figure 18</td><td>Federated return to ESTS and external account routing.</td><td>1.3.12</td><td><code>images/fig-18-consumers-federated.png</code></td></tr>
<tr><td>Figure 19</td><td>ESTS entry, interaction, and upstream OAuth handoff.</td><td>2.2.2, 2.12</td><td><code>images/fig-19-v1-v2.png</code></td></tr>
<tr><td>Figure 20</td><td>Page state, alternative SAS polling patterns, and completion state.</td><td>2.3.4</td><td><code>images/fig-20-token-lineage.png</code></td></tr>
<tr><td>Figure 21</td><td>Cookie handling before and after MFA completion.</td><td>2.20</td><td><code>images/fig-21-cookies.png</code></td></tr>
<tr><td>Figure 22</td><td>ESTS error channels and endpoint-specific recovery.</td><td>2.21</td><td><code>images/fig-22-errors.png</code></td></tr>
<tr><td>Figure 23</td><td>ESTS authorization-response delivery wrappers and upstream handoff.</td><td>2.22</td><td><code>images/fig-23-authz-response.png</code></td></tr>
</tbody></table>
