<style>
body {
  font-family: Segoe UI,SegoeUI,Helvetica Neue,Helvetica,Arial,sans-serif;
  padding: 1em;
  margin: auto;
  max-width: 42em;
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
</style>

# ESTS Interactive Multi-Factor Authentication Protocol

Specifies the HTTP APIs used by Microsoft Entra ID (ESTS) to perform
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
5. Exchange that code at the token endpoint.

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
- OAuth 2.0 device authorization grant (organizational and consumers)

All authorization-code patterns conclude by delivering `code` to the
`redirect_uri` from the original authorize request (unless an interrupt is
terminal, such as consent).

The normative terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe the
wire behavior required for conformance with this protocol.

## 1.1 Glossary

<table class="protocol-table"><thead>
  <tr><th><p>Term</p></th><th><p>Definition</p></th></tr>
</thead><tbody>
 <tr>
  <td><p>Auth Config / `$Config`</p></td>
  <td><p>JSON object embedded in ESTS HTML responses that advertises session
  state and endpoint URLs for the current authentication step.</p></td>
 </tr>
 <tr>
  <td><p>canary</p></td>
  <td><p>CSRF / request-validation token. Appears as `$Config.canary`, as a
  form field, and as an HTTP header on some JSON APIs.</p></td>
 </tr>
 <tr>
  <td><p>ctx / sCtx / request</p></td>
  <td><p>Opaque ESTS flow context. `$Config.sCtx` is posted as `ctx` or
  `request` depending on the endpoint.</p></td>
 </tr>
 <tr>
  <td><p>flowToken / sFT</p></td>
  <td><p>Opaque ESTS flow token. `$Config.sFT` is posted as `flowToken` (or
  `flowtoken` on the MFA-registration skip resume).</p></td>
 </tr>
 <tr>
  <td><p>ESTS</p></td>
  <td><p>Microsoft Entra ID Security Token Service, hosted at
  `login.microsoftonline.com`.</p></td>
 </tr>
 <tr>
  <td><p>Remote NGC</p></td>
  <td><p>Remote Next Generation Credential challenge delivered to Microsoft
  Authenticator (push / number match).</p></td>
 </tr>
 <tr>
  <td><p>SAS</p></td>
  <td><p>Strong Authentication Service endpoints under
  `/common/SAS/`.</p></td>
 </tr>
 <tr>
  <td><p>Entropy</p></td>
  <td><p>Integer shown to the user for Authenticator number matching.</p></td>
 </tr>
</tbody></table>

## 1.2 Overview

Interactive MFA over these APIs is a multi-step state machine. Every HTML
response from ESTS that advances the flow embeds a fresh `$Config`. Clients
MUST treat `sFT`, `sCtx`, `canary`, `sessionId`, and advertised URLs from the
most recent `$Config` (or SAS JSON response) as authoritative for the next
request.

Cookie jars established by ESTS (`Set-Cookie` on authorize, credential, and
login responses) MUST be returned on subsequent requests to the same host.

## 1.3 Protocol Operation Sequences

ESTS offers multiple interactive authentication paths. Which path applies is
determined by GetCredentialType capability flags / `PrefCredential`, by the
Auth Config returned after password submission (`arrUserProofs`, `pgid`), and
by interrupts ESTS inserts before issuing an authorization code.

All paths share a common prefix unless noted:

1. Optional federation provider discovery ([§2.1](#21-federation-provider-discovery)).
2. `GET /{tenant}/oauth2/authorize` and parse `$Config`
   ([§2.2](#22-oauth-20-authorize-and-auth-config-discovery),
   [§2.3](#23-auth-config-config)).
3. `POST /common/GetCredentialType` ([§2.4](#24-getcredentialtype)), except
   where a path is entered solely via the OAuth device-code grant
   ([§2.19](#219-oauth-20-device-authorization-grant)).

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
  <td><p>Federated IdP redirect (out of scope for ESTS SAS MFA)</p></td>
  <td><p>§1.3.12</p></td>
 </tr>
 <tr>
  <td><p><code>IfExistsResult == 5</code> (personal Microsoft account)</p></td>
  <td><p>Consumers device-code grant</p></td>
  <td><p>§2.19.2</p></td>
 </tr>
 <tr>
  <td><p><code>HasPassword</code> true (typical organizational account)</p></td>
  <td><p>Password submission, then branch on resulting <code>pgid</code></p></td>
  <td><p>§1.3.3 / §2.8</p></td>
 </tr>
</tbody></table>

`PrefCredential` is a numeric preference hint whose value assignments are
not a reliable method selector:

- `PrefCredential: 2` has been returned together with `HasRemoteNGC: true`, a
  populated `RemoteNgcParams`, and `FidoParams: null`.
- `PrefCredential: 1` has been returned together with `HasPassword: true` and
  every `*Params` block null.
- The values `7` (Remote NGC) and `13` (Access Pass) have also been used by
  ESTS for other account configurations, and `2` has been associated with FIDO.
  The same value therefore does not identify the same method in every
  response.

A client SHOULD therefore select a path from the presence of the
corresponding parameter blocks (`RemoteNgcParams`, `FidoParams`,
`HasAccessPass`) and MUST NOT infer a method from the numeric
`PrefCredential` alone. ESTS MAY still expose other methods in
`Credentials.*Params` or later in `arrUserProofs`. The capability request
flags on GetCredentialType (`isRemoteNGCSupported`, `isFidoSupported`,
`isAccessPassSupported`) influence which parameter blocks are populated.

### 1.3.2 Passwordless Remote NGC Sequence

1. Common prefix through GetCredentialType.
2. `POST /common/GetOneTimeCode` ([§2.5](#25-getonetimecode)).
3. Poll `POST /common/DeviceCodeStatus` until `AuthorizationState` is `2`
   ([§2.6](#26-devicecodestatus)).
4. `POST /{tenant}/login` with Remote NGC form fields
   ([§2.7](#27-login-passwordless-remote-ngc-completion)).
5. Handle any post-login interrupt ([§1.3.11](#1311-post-authentication-interrupts)),
   then exchange `code` ([§2.12](#212-authorization-code-token-exchange)).

### 1.3.3 Password Submission, Then Branch

1. Common prefix through GetCredentialType.
2. `POST /{tenant}/login` with username and password
   ([§2.8](#28-login-password-submission)).
3. Branch on the response:

<table class="protocol-table"><thead>
  <tr><th><p>Outcome</p></th><th><p>Next</p></th></tr>
</thead><tbody>
 <tr><td><p><code>302</code> with <code>code</code></p></td><td><p>No further MFA; token exchange (§2.12).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedTFA</code> with <code>arrUserProofs</code></p></td><td><p>SAS or FIDO/AccessPass proof (§1.3.6–§1.3.10).</p></td></tr>
 <tr><td><p><code>pgid=KmsiInterrupt</code></p></td><td><p>KMSI continue (§2.16).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedProofUpRedirect</code></p></td><td><p>MFA registration interrupt (§2.13 / §2.16).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedChangePassword</code></p></td><td><p>Password change / SSPR (§2.17).</p></td></tr>
 <tr><td><p><code>pgid=ConvergedConsent</code></p></td><td><p>Application consent required (terminal for this protocol).</p></td></tr>
 <tr><td><p>Auto-submit HTML (“Working…”)</p></td><td><p>POST form action until Auth Config or redirect (§2.18).</p></td></tr>
</tbody></table>

### 1.3.4 Passwordless Temporary Access Pass Sequence

1. Common prefix; GetCredentialType indicates Access Pass availability.
2. Collect the Temporary Access Pass from the user (no BeginAuth).
3. `POST` to `$Config.urlPost` with Access Pass form fields
   ([§2.15](#215-temporary-access-pass-completion)).
4. Obtain `code` (possibly after interrupts) and exchange (§2.12).

### 1.3.5 Passwordless FIDO Sequence

1. Common prefix; GetCredentialType returns `FidoParams` (allow-list).
2. `POST {urlFidoLogin}` to obtain a FIDO challenge Auth Config
   ([§2.14.1](#2141-fidologin-challenge-bootstrap)).
3. Produce a WebAuthn/FIDO assertion locally (outside ESTS HTTP).
4. `POST` the assertion to `urlPost`
   ([§2.14.2](#2142-fido-assertion-completion)).
5. Obtain `code` and exchange (§2.12).

### 1.3.6 SAS PhoneAppNotification / CompanionApps (Poll)

Entered from ConvergedTFA when `arrUserProofs` contains
`PhoneAppNotification` or `CompanionAppsNotification`.

1. `POST /common/SAS/BeginAuth` with that `AuthMethodId` ([§2.9](#29-sas-beginauth)).
2. Display `Entropy` for number matching when present.
3. Poll `GET /common/SAS/EndAuth` until `Success` ([§2.10.1](#2101-endauth-poll)).
4. `POST /common/SAS/ProcessAuth` ([§2.11](#211-sas-processauth)).
5. Handle interrupts; exchange `code`.

### 1.3.7 SAS PhoneAppOTP (Code Entry)

Entered when `arrUserProofs` contains `PhoneAppOTP` (often with
`phoneAppOtpTypes: ["MicrosoftAuthenticatorBasedTOTP"]`).

1. `POST /common/SAS/BeginAuth` with `AuthMethodId=PhoneAppOTP`.
2. Collect the TOTP from the authenticator app.
3. `POST /common/SAS/EndAuth` with `Method=EndAuth` and
   `AdditionalAuthData` set to the OTP ([§2.10.2](#2102-endauth-otp-submission)).
4. `POST /common/SAS/ProcessAuth` with `mfaAuthMethod=PhoneAppOTP`.
5. Handle interrupts; exchange `code`.

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

### 1.3.9 SAS Voice Call Methods

Entered when `arrUserProofs` contains `TwoWayVoiceMobile`,
`TwoWayVoiceAlternateMobile`, or `TwoWayVoiceOffice`.

1. `POST /common/SAS/BeginAuth` with the voice `AuthMethodId`.
2. Poll `GET /common/SAS/EndAuth` until the call is answered / approved
   (same poll contract as PhoneAppNotification).
3. `POST /common/SAS/ProcessAuth` with the same `mfaAuthMethod`.
4. Handle interrupts; exchange `code`.

### 1.3.10 FIDO or Access Pass From ConvergedTFA

After password login, `arrUserProofs` MAY list `FidoKey` or `AccessPass`
alongside SAS methods.

- __FidoKey__: Bootstrap via `urlFidoLogin` using `arrFidoAllowList` from the
  ConvergedTFA Auth Config (or GetCredentialType `FidoParams.AllowList`),
  then complete with assertion POST ([§2.14](#214-fido-authentication)).
  BeginAuth is not used for FidoKey.
- __AccessPass__: Collect TAP and POST to `urlPost` ([§2.15](#215-temporary-access-pass-completion)).
  BeginAuth is not used for AccessPass.

### 1.3.11 Post-Authentication Interrupts

After MFA success (ProcessAuth, passwordless login, or FIDO/TAP completion),
ESTS MAY return HTML instead of an authorization-code redirect:

<table class="protocol-table"><thead>
  <tr><th><p>pgid / condition</p></th><th><p>Wire handling</p></th></tr>
</thead><tbody>
 <tr>
  <td><p><code>KmsiInterrupt</code></p></td>
  <td><p>POST <code>urlPost</code> with <code>LoginOptions=1</code>, <code>ctx</code>, <code>flowToken</code>, <code>canary</code>
  ([§2.16](#216-kmsi-and-proofup-continue-posts)).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedProofUpRedirect</code> with <code>urlSkipMfaRegistration</code></p></td>
  <td><p>Either complete registration (out of scope) or POST skip resume
  ([§2.13](#213-skip-mfa-registration-resume)). When remaining skip days
  are advertised, a <code>LoginOptions=1</code> continue POST on the current
  <code>urlPost</code> MAY also advance the flow ([§2.16](#216-kmsi-and-proofup-continue-posts)).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedChangePassword</code></p></td>
  <td><p>Password change via SSPR begin/poll endpoints from Auth Config
  ([§2.17](#217-password-change-sspr)).</p></td>
 </tr>
 <tr>
  <td><p><code>ConvergedConsent</code></p></td>
  <td><p>Admin/user consent required; no further MFA API advances the flow.</p></td>
 </tr>
 <tr>
  <td><p>Auto-submit / “Working…” HTML</p></td>
  <td><p>Parse and POST the HTML form until redirect or Auth Config
  ([§2.18](#218-intermediate-auto-submit-html)).</p></td>
 </tr>
</tbody></table>

### 1.3.12 Federated Identities

When GetCredentialType returns `Credentials.FederationRedirectUrl`, ESTS
expects a browser redirect to an external IdP. The SAS / Remote NGC APIs in
this document do not complete that federation handshake. Clients that cannot
follow the federated redirect MUST use a different grant (for example the
device authorization grant in [§2.19](#219-oauth-20-device-authorization-grant)).

### 1.3.13 Device Authorization Grant (Browser on Another Device)

As an alternate interactive MFA channel, ESTS supports RFC 8628 device
authorization at `/oauth2/v2.0/devicecode` and `/oauth2/v2.0/token`
([§2.19](#219-oauth-20-device-authorization-grant)). The user completes MFA in
a browser at the verification URI. Organizational and consumers
(`login.microsoftonline.com/consumers`) variants exist.

### 1.3.14 Forcing NGC MFA on Authorize

The v1 authorize endpoint accepts `amr_values=ngcmfa`, which requests that
ESTS require NGC MFA for the authentication regardless of other policy. The
parameter is not supported on `/oauth2/v2.0/authorize` and is not listed in
public parameter tables; see [§2.2.2](#222-v1-and-v2-authorize-differences).
Password-change sign-ins omit it ([§2.17](#217-password-change-sspr)).

## 1.4 Completeness of Field Descriptions

Request and response field sets for the Remote NGC and password plus SAS
paths are given in full. For the FIDO, Temporary Access Pass, PhoneAppOTP /
SMS / voice SAS, KMSI and ProofUp continue, SSPR and consumers device-code
paths, the fields listed are those a client needs to send and consume; ESTS
responses on those paths MAY carry additional fields that a client ignores.
Values shown in examples (GUIDs, tokens, timings) are representative, not
mandated.

# 2 Protocol Details

## 2.1 Federation Provider Discovery

### 2.1.1 federationProvider

#### 2.1.1.1 GET

This method is transported by an HTTP GET.

##### 2.1.1.1.1 Request

<pre><code>GET https://odc.officeapps.live.com/odc/v2.1/federationProvider?domain={domain}
</code></pre>

`domain` is the DNS suffix of the user principal name (the part after `@`).

##### 2.1.1.1.2 Response Body

On success the response is `200` with `Content-Type: application/json` and a
body of the form:

<pre><code class="lang-json">{
  "environment": "Global",
  "endpoint": [
    {
      "type": "MSA",
      "authentication_endpoint": "https://login.live.com/oauth20_authorize.srf",
      "token_endpoint": "https://login.live.com/oauth20_token.srf"
    },
    {
      "type": "OrgId",
      "authentication_endpoint": "https://login.microsoftonline.com/common/oauth2/authorize",
      "token_endpoint": "https://login.microsoftonline.com/common/oauth2/token"
    }
  ],
  "tenantId": "string (GUID)",
  "authority_host": "login.microsoftonline.com",
  "graph": "https://graph.microsoft.com"
}
</code></pre>

__tenantId__: The Entra ID tenant GUID for the domain. Used to build
tenant-scoped ESTS URLs.

__endpoint__: Authentication and token endpoints for Microsoft account (MSA)
and organizational (OrgId) identities.

##### 2.1.1.1.3 Processing Details

For organizational MFA the client SHOULD use `tenantId` and
`authority_host` from this response when constructing subsequent ESTS
requests. The OrgId authorize and token endpoints listed here are the
common (`/common`) variants; tenant-scoped URLs of the form
`https://{authority_host}/{tenantId}/...` are also valid and are used
in MFA flows.

## 2.2 OAuth 2.0 Authorize and Auth Config Discovery

### 2.2.1 authorize

#### 2.2.1.1 GET

This method is transported by an HTTP GET to ESTS.

##### 2.2.1.1.1 Request

<pre><code>GET https://login.microsoftonline.com/{tenant}/oauth2/authorize?{query}
</code></pre>

Query parameters:

<table class="protocol-table"><thead>
  <tr><th><p>Parameter</p></th><th><p>Required</p></th><th><p>Description</p></th></tr>
</thead><tbody>
 <tr><td><p>client_id</p></td><td><p>Yes</p></td><td><p>Application (client) ID.</p></td></tr>
 <tr><td><p>response_type</p></td><td><p>Yes</p></td><td><p>MUST be <code>code</code> for the flows in this document.</p></td></tr>
 <tr><td><p>redirect_uri</p></td><td><p>Yes</p></td><td><p>Registered redirect URI. Custom schemes such as
 <code>ms-aadj-redir://auth/drs</code> are accepted for device enrollment clients.</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>No</p></td><td><p>Correlation GUID for the client request.</p></td></tr>
 <tr><td><p>prompt</p></td><td><p>No</p></td><td><p>Value <code>login</code> forces interactive credential collection.</p></td></tr>
 <tr><td><p>scope</p></td><td><p>No</p></td><td><p>Space-delimited scopes (for example <code>openid profile</code>).</p></td></tr>
 <tr><td><p>response_mode</p></td><td><p>No</p></td><td><p>Value <code>query</code> returns the response parameters in the redirect query string.</p></td></tr>
 <tr><td><p>sso_reload</p></td><td><p>No</p></td><td><p>Value <code>True</code> is sent on v1 authorize requests.</p></td></tr>
 <tr><td><p>resource</p></td><td><p>No</p></td><td><p>v1 resource identifier (for example
 <code>https://enrollment.manage.microsoft.com/</code>). Used with the v1 authorize
 endpoint.</p></td></tr>
 <tr><td><p>caller_app_client_id</p></td><td><p>No</p></td><td><p>Calling application client ID when acting as a broker.</p></td></tr>
 <tr><td><p>caller_app_redirect_uri</p></td><td><p>No</p></td><td><p>Calling application redirect URI when acting as a broker.</p></td></tr>
 <tr><td><p>amr_values</p></td><td><p>No</p></td><td><p>When set to <code>ngcmfa</code>, ESTS is requested to require NGC MFA claims
 in the resulting authentication. Supported on v1 only (see
 [§2.2.2](#222-v1-and-v2-authorize-differences)).</p></td></tr>
 <tr><td><p>login_hint</p></td><td><p>No</p></td><td><p>Pre-fills the username.</p></td></tr>
 <tr><td><p>domain_hint</p></td><td><p>No</p></td><td><p>Skips email-based realm discovery (v2.0).</p></td></tr>
 <tr><td><p>state</p></td><td><p>No</p></td><td><p>Opaque value returned unchanged on the redirect.</p></td></tr>
 <tr><td><p>code_challenge / code_challenge_method</p></td><td><p>No</p></td><td><p>PKCE parameters. When omitted, the token request needs no <code>code_verifier</code>.</p></td></tr>
</tbody></table>

`{tenant}` is a tenant GUID, `common`, `organizations`, `consumers`, or a
verified domain name.

A `scope` value of `openid profile ` (note the trailing space) is accepted;
ESTS preserves it in the form-encoded `scope=openid+profile+` reproduced
inside `urlTenantedEndpointFormat` ([§2.3.1](#231-common-fields)).
Request headers on authorize: `User-Agent`, `Accept: */*`, and `Host`
only. No cookies are sent on the first request.

##### 2.2.1.1.2 Response Body

On interactive sign-in the response is `200` with `Content-Type: text/html`
and one or more `Set-Cookie` headers. The HTML body contains a script block
that assigns the Auth Config object:

<pre><code>$Config={...};
</code></pre>

The exact byte structure of the script element, for every page that carries
an Auth Config, is:

<pre><code>&lt;script type="text/javascript" nonce='{nonce}'&gt;//&lt;![CDATA[
$Config={...JSON object...};
//]]&gt;&lt;/script&gt;
</code></pre>

That is: `//<![CDATA[` and a line feed, the literal `$Config=`, a single JSON
object, then `;`, a line feed, `//]]>` and `</script>`. Notes:

- The HTML document contains several other `<script>` elements, additional
  `//]]>` markers outside the Auth Config element, and further occurrences of
  the token `$Config` (inside page script that reads the object), but exactly
  one `$Config=` assignment.
- The JSON object uses `\u0026` for every `&` (no literal `&` appears). A standard JSON parser decodes these; a client that
  extracts URLs by other means MUST decode them.
- The Auth Config is large: on the order of 200 top-level keys on
  ConvergedSignIn and 100 to 160 on ConvergedTFA and ConvergedProofUpRedirect.
  Most keys are
  UI feature flags (`fEnable*`) and string tables; the keys a non-browser
  client consumes are listed in [§2.3](#23-auth-config-config).
- The HTML body begins with CRLF-separated whitespace and a comment, followed
  by `<!DOCTYPE html>`.

##### 2.2.1.1.3 Processing Details

The client MUST:

1. Persist cookies from the response.
2. Locate the `$Config=` assignment in a `<script>` element.
3. Parse the JSON object that follows through the matching closing `}` of that
   assignment. Because `;\n//]]>` follows the object directly, the object text
   equals the script text after `$Config=` up to the last `//]]>` in that same
   script element, minus the two trailing characters `;` and line feed.
4. Retain the fields listed in [§2.3](#23-auth-config-config) for subsequent
   calls.

Initial authorize responses include `sErrorCode: "50058"` and
`arrValErrs: ["50058"]` (user not signed in) on ConvergedSignIn. That value describes page state for the HTML UI and MUST NOT be
treated as fatal at this step. The same fields on later pages carry real
failures (see [§2.21](#221-error-signaling)).

The authorize response also sets the initial cookie set described in
[§2.20](#220-session-cookies-and-response-headers) and returns the first
`sFT`, `sCtx`, `canary`, `apiCanary`, `sCrossDomainCanary` and `sessionId`.

### 2.2.2 v1 and v2 Authorize Differences

The interactive MFA API in this document is specified against the v1
authorize endpoint (`/{tenant}/oauth2/authorize`). The table below lists the
differences between the v1 and v2.0 (`/oauth2/v2.0/authorize`) endpoints that
affect a non-browser client.

<table class="protocol-table"><thead>
  <tr><th><p>Aspect</p></th><th><p>v1 (<code>/oauth2/authorize</code>)</p></th><th><p>v2.0 (<code>/oauth2/v2.0/authorize</code>)</p></th></tr>
</thead><tbody>
 <tr><td><p>Authorize path</p></td><td><p><code>/{tenant}/oauth2/authorize</code></p></td><td><p><code>/{tenant}/oauth2/v2.0/authorize</code>. Path matching is case-insensitive (<code>oAuth2/v2.0/authorize</code> is accepted).</p></td></tr>
 <tr><td><p>Token path</p></td><td><p><code>/{tenant}/oauth2/token</code></p></td><td><p><code>/{tenant}/oauth2/v2.0/token</code></p></td></tr>
 <tr><td><p>Device code path</p></td><td><p>Not applicable.</p></td><td><p><code>/{tenant}/oauth2/v2.0/devicecode</code>; consumers: <code>/consumers/oauth2/v2.0/devicecode</code></p></td></tr>
 <tr><td><p>Target API selector</p></td><td><p><code>resource</code>: App ID URI of the target API (for example <code>https://enrollment.manage.microsoft.com/</code>). Required in either the authorize or the token request. When omitted no resource-specific Conditional Access (and therefore no MFA requirement) is evaluated.</p></td><td><p><code>scope</code>: space-delimited, resource-qualified scopes (for example <code>https://graph.microsoft.com/mail.read</code>, or <code>{resource}/.default</code>). <code>resource</code> is not part of the documented parameter set.</p></td></tr>
 <tr><td><p><code>scope</code> parameter</p></td><td><p>Ignored for v1 applications (permissions are statically configured). A v1 request MAY nevertheless send <code>scope=openid profile </code> alongside <code>resource</code>; it is accepted, and the token response <code>scope</code> carries the granted permissions (for example <code>mdm_delegation</code>).</p></td><td><p>Required. Determines both the consent and the resource of the issued access token. The <code>/token</code> request MAY repeat <code>scope</code> to name a single resource.</p></td></tr>
 <tr><td><p><code>redirect_uri</code></p></td><td><p>Recommended. A custom scheme (<code>ms-aadj-redir://auth/drs</code>) is accepted for the enrollment client and the code is returned on that URI.</p></td><td><p>Required; MUST match a registered value exactly.</p></td></tr>
 <tr><td><p><code>prompt</code> values</p></td><td><p><code>login</code>, <code>select_account</code>, <code>consent</code>, <code>admin_consent</code>.</p></td><td><p><code>login</code>, <code>none</code>, <code>consent</code>, <code>select_account</code>. <code>none</code> returns <code>login_required</code> / <code>interaction_required</code> rather than an Auth Config page.</p></td></tr>
 <tr><td><p><code>sso_reload</code>, <code>caller_app_client_id</code>, <code>caller_app_redirect_uri</code></p></td><td><p>Accepted. Not listed in public parameter tables.</p></td><td><p>Not supported.</p></td></tr>
 <tr><td><p><code>amr_values=ngcmfa</code></p></td><td><p>Requests NGC MFA; used when the client wants MFA enforced irrespective of policy. Not listed in public parameter tables. When it is omitted, ESTS still issues <code>amr: ["pwd","mfa"]</code> if the sign-in required MFA by policy.</p></td><td><p>Not supported.</p></td></tr>
 <tr><td><p><code>state</code>, <code>nonce</code>, PKCE</p></td><td><p><code>state</code> is supported; PKCE is not part of the v1 parameter set.</p></td><td><p><code>state</code>, <code>nonce</code> (hybrid), <code>code_challenge</code>, <code>code_challenge_method</code> are supported. PKCE is required for SPA redirect URIs.</p></td></tr>
 <tr><td><p>Interactive endpoints after authorize</p></td><td><p>GetCredentialType, GetOneTimeCode, DeviceCodeStatus, <code>login</code>, SAS BeginAuth / EndAuth / ProcessAuth, <code>resume</code> are all addressed by absolute URLs inside the Auth Config. None of them carries an endpoint-version marker.</p></td><td><p>The interactive MFA API is reached through the v1 endpoint; v2.0 is used for non-interactive (PRT-bearing) code requests.</p></td></tr>
 <tr><td><p>Auth Config echo of the request</p></td><td><p><code>urlTenantedEndpointFormat</code> reproduces the v1 authorize URL with <code>{0}</code> in place of the tenant, appends <code>allowbacktocommon=True</code>, and keeps the original parameter order and encoding (<code>%3a%2f%2f</code> lower-case hex).</p></td><td><p>Not specified.</p></td></tr>
 <tr><td><p>Authorization response</p></td><td><p><code>302</code> to <code>redirect_uri</code> with <code>code</code> and <code>session_state</code> (a GUID; it equals the <code>sid</code> claim of the issued tokens); errors as <code>error</code> / <code>error_description</code> on the redirect URI.</p></td><td><p>Same shape plus <code>state</code> echo; <code>response_mode</code> <code>query</code>, <code>fragment</code>, <code>form_post</code>.</p></td></tr>
 <tr><td><p>Token request fields</p></td><td><p><code>client_id</code>, <code>grant_type</code>, <code>code</code>, <code>redirect_uri</code>. <code>resource</code> is optional when it was sent to authorize. The request MAY omit <code>resource</code>, <code>scope</code>, <code>client-request-id</code> and <code>code_verifier</code>.</p></td><td><p><code>client_id</code>, <code>grant_type</code>, <code>code</code>, <code>redirect_uri</code>, optional <code>scope</code>, <code>code_verifier</code> when PKCE was used.</p></td></tr>
 <tr><td><p>Token response</p></td><td><p>Numbers are JSON strings: <code>expires_in</code>, <code>ext_expires_in</code>, <code>expires_on</code>, <code>not_before</code>. Includes <code>resource</code> and <code>scope</code> (granted permissions). A refresh token and an ID token are returned for requested scope <code>openid profile</code> (no <code>offline_access</code> is needed).</p></td><td><p><code>expires_in</code> is a JSON number. No <code>resource</code>, <code>expires_on</code>, <code>not_before</code>. <code>scope</code> echoes granted scopes. <code>refresh_token</code> only with <code>offline_access</code>; <code>id_token</code> only with <code>openid</code>.</p></td></tr>
 <tr><td><p>Access token version</p></td><td><p>Not determined by the endpoint version. A token issued through the v1 endpoint can have <code>ver: "1.0"</code> and <code>iss</code> of the form <code>https://sts.windows.net/{tid}/</code>.</p></td><td><p>The access token version is selected by the target resource (<code>requestedAccessTokenVersion</code>); either endpoint can issue either version. The issuer of a v2.0 token is <code>https://login.microsoftonline.com/{tid}/v2.0</code>.</p></td></tr>
 <tr><td><p>Error body at <code>/token</code></p></td><td><p><code>error</code>, <code>error_description</code> (begins <code>AADSTS{code}:</code>), <code>error_codes</code>, <code>timestamp</code>, <code>trace_id</code>, <code>correlation_id</code>.</p></td><td><p>Same fields.</p></td></tr>
 <tr><td><p>Silent code request with PRT / device assertions</p></td><td><p>Request headers <code>x-ms-RefreshTokenCredential</code> and <code>x-ms-DeviceCredential</code> carry signed JWT assertions; <code>resource</code> selects the API.</p></td><td><p>Same headers; <code>scope</code> selects the API; <code>redirect_uri</code> and <code>client_id</code> may identify an on-behalf-of client.</p></td></tr>
</tbody></table>

Unspecified: whether the
ConvergedSignIn Auth Config served from the v2.0 authorize endpoint
contains the same `urlGetCredentialType`, `urlGetOneTimeCode`,
`urlSessionState`, `urlBeginAuth`, `urlEndAuth` and `urlPost` values; whether
v2.0 honors any equivalent of `amr_values=ngcmfa`; and whether the sessions
produced from either endpoint are interchangeable at `ProcessAuth` and
`login`. A conforming server that exposes the browserless API on both endpoints
should keep the Auth Config API surface identical.

### 2.2.3 Client Identifiers and Redirect URIs

The `redirect_uri` sent on authorize MUST equal the one sent on the token
request, and ESTS accepts a registered value per client identifier. The
pairs below are the registered values used with this API.

<table class="protocol-table"><thead>
  <tr><th><p><code>client_id</code></p></th><th><p><code>redirect_uri</code></p></th><th><p>Condition</p></th></tr>
</thead><tbody>
 <tr><td><p><code>29d9ed98-a469-4536-ade2-f981bc1d605e</code></p></td><td><p><code>ms-aadj-redir://auth/drs</code></p></td><td><p><code>resource</code> contains <code>enrollment.manage.microsoft.com</code></p></td></tr>
 <tr><td><p><code>29d9ed98-a469-4536-ade2-f981bc1d605e</code></p></td><td><p><code>msauth://Microsoft.AAD.BrokerPlugin</code></p></td><td><p>any other <code>resource</code></p></td></tr>
 <tr><td><p><code>b743a22d-6705-4147-8670-d92fa515ee2b</code></p></td><td><p><code>companyportal://com.microsoft.CompanyPortal</code></p></td><td><p>sent as <code>caller_app_client_id</code> / <code>caller_app_redirect_uri</code></p></td></tr>
 <tr><td><p><code>1fec8e78-bce4-4aaf-ab1b-5451cc387264</code>, <code>fb78d390-0c51-40cd-8e17-fdbfab77341b</code>, <code>fdd7719f-d61e-4592-b501-793734eb8a0e</code>, <code>a0c73c16-a7e3-4564-9a95-2bdf47383716</code></p></td><td><p><code>https://login.microsoftonline.com/common/oauth2/nativeclient</code></p></td><td><p>also the default for any client not listed</p></td></tr>
 <tr><td><p><code>ab9b8c07-8f02-4f72-87fa-80105867a763</code></p></td><td><p><code>https://login.windows.net/common/oauth2/nativeclient</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>c44b4083-3bb0-49c1-b47d-974e53cbdf3c</code></p></td><td><p><code>https://portal.azure.com/signin/index/?feature.prefetchtokens=true&feature.showservicehealthalerts=true&feature.usemsallogin=true</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>19db86c3-b2b9-44cc-b339-36da233a3be2</code></p></td><td><p><code>https://mysignins.microsoft.com</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>0000000c-0000-0000-c000-000000000000</code></p></td><td><p><code>https://account.activedirectory.windowsazure.com/</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>d3590ed6-52b3-4102-aeff-aad2292ab01c</code></p></td><td><p><code>ms-appx-web://Microsoft.AAD.BrokerPlugin/d3590ed6-52b3-4102-aeff-aad2292ab01c</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>dd762716-544d-4aeb-a526-687b73838a22</code></p></td><td><p><code>ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>9bc3ab49-b65d-410a-85ad-de819febfddc</code></p></td><td><p><code>https://oauth.spops.microsoft.com/</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>3b511579-5e00-46e1-a89e-a6f0870e2f5a</code></p></td><td><p><code>https://windows365.microsoft.com/signin-oidc</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>4765445b-32c6-49b0-83e6-1d93765276ca</code></p></td><td><p><code>https://www.office.com/landingv2</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>33be1cef-03fb-444b-8fd3-08ca1b4d803f</code></p></td><td><p><code>https://admin.onedrive.com/</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>3d5cffa9-04da-4657-8cab-c7f074657cad</code></p></td><td><p><code>http://localhost/m365/commerce</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>4990cffe-04e8-4e8b-808a-1175604b879f</code></p></td><td><p><code>https://partner.microsoft.com/aad/authPostGateway</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>0c1307d4-29d6-4389-a11c-5cbe7f65d7fa</code></p></td><td><p><code>https://azureapp</code></p></td><td><p>Client-specific</p></td></tr>
 <tr><td><p><code>08e18876-6177-487e-b8b5-cf950c1e598c</code></p></td><td><p><code>https://*-admin.sharepoint.com/_forms/spfxsinglesignon.aspx</code></p></td><td><p>Client-specific</p></td></tr>
</tbody></table>

An interactive-browser variant of the v1 request uses
`redirect_uri=https://login.microsoftonline.com/applebroker/msauth`,
`login_hint`, `response_mode=query`, `resource` and `amr_values=ngcmfa`, and
reads the code from the final navigation URL.

## 2.3 Auth Config (`$Config`)

Auth Config is not a standalone HTTP resource. It is the control plane for
ESTS interactive flows and is reissued whenever ESTS returns HTML.

### 2.3.1 Common Fields

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Type</p></th><th><p>Description</p></th></tr>
</thead><tbody>
 <tr><td><p>sessionId</p></td><td><p>string</p></td><td><p>ESTS session identifier. Used as <code>x-ms-sessionId</code> on SAS
 EndAuth polling. On every page that carries an Auth Config (ConvergedSignIn, ConvergedTFA, ConvergedProofUpRedirect) it is
 equal to the <code>x-ms-request-id</code> response header of the response that rendered the page, so it changes on every
 Auth Config page.</p></td></tr>
 <tr><td><p>sFT</p></td><td><p>string</p></td><td><p>Flow token. Posted as <code>flowToken</code>.</p></td></tr>
 <tr><td><p>sFTName</p></td><td><p>string</p></td><td><p>Form field name for the flow token (value <code>flowToken</code>).</p></td></tr>
 <tr><td><p>sCtx</p></td><td><p>string</p></td><td><p>Flow context. Posted as <code>ctx</code> or <code>request</code>.</p></td></tr>
 <tr><td><p>canary</p></td><td><p>string</p></td><td><p>Request validation token.</p></td></tr>
 <tr><td><p>apiCanary</p></td><td><p>string</p></td><td><p>Alternate canary used by some ESTS instrumentation APIs.</p></td></tr>
 <tr><td><p>correlationId</p></td><td><p>string</p></td><td><p>Correlation GUID.</p></td></tr>
 <tr><td><p>sTenantId</p></td><td><p>string</p></td><td><p>Tenant GUID.</p></td></tr>
 <tr><td><p>pgid</p></td><td><p>string</p></td><td><p>Page identifier describing the current interrupt. See
 [§2.3.3](#233-page-identifiers-pgid).</p></td></tr>
 <tr><td><p>urlPost</p></td><td><p>string</p></td><td><p>URL for the next form POST that advances the flow.</p></td></tr>
 <tr><td><p>urlGetCredentialType</p></td><td><p>string</p></td><td><p>URL for GetCredentialType. Example:
 <code>https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US</code>.</p></td></tr>
 <tr><td><p>urlGetOneTimeCode</p></td><td><p>string</p></td><td><p>URL for GetOneTimeCode.</p></td></tr>
 <tr><td><p>urlSessionState</p></td><td><p>string</p></td><td><p>URL for DeviceCodeStatus polling.</p></td></tr>
 <tr><td><p>urlBeginAuth</p></td><td><p>string</p></td><td><p>URL for SAS BeginAuth. Present after password MFA interrupt.</p></td></tr>
 <tr><td><p>urlEndAuth</p></td><td><p>string</p></td><td><p>URL for SAS EndAuth. Present after password MFA interrupt.</p></td></tr>
 <tr><td><p>arrUserProofs</p></td><td><p>array</p></td><td><p>Available MFA methods after password validation. See
 [§2.3.2](#232-arruserproofs).</p></td></tr>
 <tr><td><p>iMaxPollAttempts</p></td><td><p>number</p></td><td><p>Maximum EndAuth poll attempts (<code>10</code> on ConvergedTFA).</p></td></tr>
 <tr><td><p>iPollingInterval</p></td><td><p>number</p></td><td><p>Polling interval. On ConvergedTFA this is milliseconds (value
 <code>5000</code>; clients poll EndAuth about every 5.1–5.3 s). On ConvergedSignIn
 the value is <code>1</code> and the page does not state a unit; clients poll DeviceCodeStatus
 about every 5.1 s and ESTS accepts that cadence.</p></td></tr>
 <tr><td><p>urlSkipMfaRegistration</p></td><td><p>string</p></td><td><p>Resume URL that skips MFA method registration interrupt.</p></td></tr>
 <tr><td><p>iRemainingDaysToSkipMfaRegistration</p></td><td><p>number</p></td><td><p>Remaining days allowed to postpone MFA registration, when present.</p></td></tr>
 <tr><td><p>sErrorCode</p> / <p>iErrorCode</p></td><td><p>string / number</p></td><td><p>AADSTS-style error when the page represents a failure or interrupt.</p></td></tr>
 <tr><td><p>sErrTxt</p> / <p>strServiceExceptionMessage</p></td><td><p>string</p></td><td><p>Human-readable error text when present.</p></td></tr>
 <tr><td><p>urlFidoLogin</p></td><td><p>string</p></td><td><p>FIDO assertion posting endpoint when FIDO is offered.</p></td></tr>
 <tr><td><p>sFidoChallenge</p></td><td><p>string</p></td><td><p>FIDO challenge material when present on the sign-in page.</p></td></tr>
 <tr><td><p>arrFidoAllowList</p></td><td><p>array</p></td><td><p>Allowed FIDO credential descriptors when present.</p></td></tr>
 <tr><td><p>sCrossDomainCanary</p></td><td><p>string</p></td><td><p>Canary used when posting FIDO assertions.</p></td></tr>
 <tr><td><p>fEnableNumberMatching</p></td><td><p>boolean</p></td><td><p>Whether Authenticator number matching is enabled for the tenant UX.</p></td></tr>
 <tr><td><p>sSessionIdentifierName</p></td><td><p>string</p></td><td><p>Value <code>code</code>; names the Remote NGC session form field.</p></td></tr>
 <tr><td><p>sCanaryTokenName</p></td><td><p>string</p></td><td><p>Value <code>canary</code>; names the canary form field.</p></td></tr>
 <tr><td><p>iPollingTimeout</p></td><td><p>number</p></td><td><p><code>300</code> on ConvergedSignIn: the overall Remote NGC polling window. The unit is not stated; 300 is consistent with seconds.</p></td></tr>
 <tr><td><p>iMaxPollErrors</p></td><td><p>number</p></td><td><p><code>5</code> on ConvergedSignIn: transport or server errors the page tolerates while polling.</p></td></tr>
 <tr><td><p>iRemoteNgcPollingType</p></td><td><p>number</p></td><td><p>Value <code>2</code>. Selects the polling mechanism the page uses for Remote NGC; value <code>2</code> corresponds to <code>urlSessionState</code> DeviceCodeStatus polling.</p></td></tr>
 <tr><td><p>iAllowedIdentities</p></td><td><p>number</p></td><td><p>Value <code>2</code>. Posted as <code>allowedIdentities</code> to <code>urlFidoLogin</code>.</p></td></tr>
 <tr><td><p>urlCancel</p></td><td><p>string</p></td><td><p>The <code>redirect_uri</code> with <code>error=access_denied&amp;error_subcode=cancel</code> appended. Navigating to it is the protocol's cancellation signal.</p></td></tr>
 <tr><td><p>urlLogin / urlRefresh</p></td><td><p>string</p></td><td><p><code>https://login.microsoftonline.com/{tenant}/reprocess?ctx={sCtx}</code>. Replays the current page state. Not used by any path here.</p></td></tr>
 <tr><td><p>urlResume</p></td><td><p>string</p></td><td><p>ConvergedSignIn: <code>…/{tenant}/resume?ctx={sCtx}</code>; ConvergedTFA: <code>…/{tenant}/resume</code> with no query.</p></td></tr>
 <tr><td><p>urlTenantedEndpointFormat</p></td><td><p>string</p></td><td><p>The authorize URL that produced the page with the tenant replaced by <code>{0}</code> and <code>allowbacktocommon=True</code> appended. See [§2.2.2](#222-v1-and-v2-authorize-differences).</p></td></tr>
 <tr><td><p>urlPostAad / urlPostMsa / urlPIAEndAuth / urlStartTlr</p></td><td><p>string</p></td><td><p>Advertised on ConvergedSignIn: <code>urlPostAad</code> equals the tenant <code>login</code> URL; <code>urlPostMsa</code> is a consumer-IdP partner post; <code>urlPIAEndAuth</code> is <code>/common/PIA/EndAuth</code>; <code>urlStartTlr</code> is <code>/{tenant}/tlr/start</code>. None is exercised by a path in this document.</p></td></tr>
 <tr><td><p>browser</p></td><td><p>object</p></td><td><p>ESTS' parse of the request <code>User-Agent</code>: <code>b.name</code>, <code>b.major</code>, <code>os.name</code>, plus capability flags. For example <code>Firefox</code> 131 / <code>Linux</code> for a Firefox 131 user agent string. Server-side capability decisions (for example FIDO) are evaluated against this value.</p></td></tr>
 <tr><td><p>serverDetails</p></td><td><p>object</p></td><td><p>Datacenter (<code>dc</code>), slice, and build (<code>ver.v</code> = <code>[2,1,25449,3]</code>) of the node that rendered the page. Corresponds to the build and slice naming of the <code>x-ms-ests-server</code> response header ([§2.20](#220-session-cookies-and-response-headers)).</p></td></tr>
 <tr><td><p>country / locale / sMkt / sRingId / sTenantId</p></td><td><p>mixed</p></td><td><p>For example <code>US</code>, <code>{mkt:"en-US",lcid:1033}</code>, <code>en-US</code>, <code>R4</code>, and the tenant GUID respectively.</p></td></tr>
</tbody></table>

Only the fields in the table above (plus `sFT`, `sCtx`, `canary`, `sessionId`,
`urlPost`, `pgid`, error fields and the URL fields) are consumed by a
non-browser client. The remaining keys (`fEnable*` UI feature flags, `strings`,
branding, `clientEvents`, `desktopSsoConfig`, `bsso`, `watson`, and others) are
not needed to construct any request in this document.

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

### 2.3.3 Page Identifiers (`pgid`)

<table class="protocol-table"><thead>
  <tr><th><p>pgid</p></th><th><p>Meaning</p></th></tr>
</thead><tbody>
 <tr><td><p>ConvergedSignIn</p></td><td><p>Initial username / password page. Advertises GetCredentialType /
 GetOneTimeCode / DeviceCodeStatus.</p></td></tr>
 <tr><td><p>ConvergedTFA</p></td><td><p>MFA interrupt after password. Advertises urlBeginAuth, urlEndAuth,
 arrUserProofs; urlPost points at ProcessAuth.</p></td></tr>
 <tr><td><p>ConvergedProofUpRedirect</p></td><td><p>MFA method registration campaign interrupt. Typically <code>sErrorCode</code> <code>50203</code>,
 <code>urlSkipMfaRegistration</code> present, <code>sCtx</code> absent, <code>urlPost</code> pointing at a
 different host (<code>https://mysignins.microsoft.com:443/api/post/registerMfaMethods?culture=en-US&amp;requirement=RegistrationCampaign&amp;authMethods=32&amp;authMethodCount=1</code>)
 that implements registration (not specified here), <code>fIsRegistrationCampaignInterrupt</code> and
 <code>fIsFidoRegistrationCampaign</code> true, and no <code>iRemainingDaysToSkipMfaRegistration</code>.</p></td></tr>
 <tr><td><p>KmsiInterrupt</p></td><td><p>“Keep me signed in” prompt.</p></td></tr>
 <tr><td><p>ConvergedChangePassword</p></td><td><p>Password change required.</p></td></tr>
 <tr><td><p>ConvergedConsent</p></td><td><p>Application consent required.</p></td></tr>
</tbody></table>

### 2.3.4 State Token Lineage

ESTS state tokens (`sFT`, `sCtx`, `canary`) are opaque. The table records which
issued value each request carries, since several JSON
responses return a `FlowToken` that the next request does **not** use.

<table class="protocol-table"><thead>
  <tr><th><p>Request</p></th><th><p>Field</p></th><th><p>Value taken from</p></th></tr>
</thead><tbody>
 <tr><td><p>GetCredentialType</p></td><td><p><code>flowToken</code>, <code>originalRequest</code></p></td><td><p>authorize <code>$Config.sFT</code>, <code>sCtx</code></p></td></tr>
 <tr><td><p>GetOneTimeCode</p></td><td><p><code>FlowToken</code>, <code>OriginalRequest</code>; header <code>canary</code></p></td><td><p>authorize <code>sFT</code>, <code>sCtx</code>, <code>canary</code> (the identical values sent to GetCredentialType)</p></td></tr>
 <tr><td><p>DeviceCodeStatus</p></td><td><p>header <code>canary</code>; no flow token</p></td><td><p>authorize <code>canary</code></p></td></tr>
 <tr><td><p>login (Remote NGC)</p></td><td><p><code>flowToken</code>, <code>ctx</code>, <code>canary</code>; <code>code</code> and <code>psRNGCSLK</code></p></td><td><p>authorize <code>sFT</code>, <code>sCtx</code>, <code>canary</code>; the <code>SessionIdentifier</code> returned by GetCredentialType (byte-identical to the one returned by GetOneTimeCode)</p></td></tr>
 <tr><td><p>login (password)</p></td><td><p><code>flowToken</code>, <code>ctx</code>, <code>canary</code></p></td><td><p>authorize <code>sFT</code>, <code>sCtx</code>, <code>canary</code>. The <code>FlowToken</code> and <code>apiCanary</code> returned by GetCredentialType were not used. <code>client-request-id</code> was a fresh GUID, different from the authorize <code>client-request-id</code>.</p></td></tr>
 <tr><td><p>BeginAuth</p></td><td><p><code>flowToken</code>, <code>ctx</code>; header <code>canary</code></p></td><td><p>ConvergedTFA <code>sFT</code>, <code>sCtx</code>, <code>canary</code></p></td></tr>
 <tr><td><p>EndAuth (poll)</p></td><td><p>headers <code>x-ms-flowToken</code>, <code>x-ms-ctx</code></p></td><td><p>The BeginAuth response <code>FlowToken</code> and <code>Ctx</code>, identical on all eight polls. Each pending response returned a different <code>FlowToken</code> (eight distinct values); none was used.</p></td></tr>
 <tr><td><p>EndAuth (poll)</p></td><td><p>header <code>x-ms-sessionId</code></p></td><td><p>ConvergedTFA <code>$Config.sessionId</code> (not the SAS JSON <code>SessionId</code>)</p></td></tr>
 <tr><td><p>ProcessAuth</p></td><td><p><code>flowToken</code>, <code>request</code>, <code>canary</code></p></td><td><p>The final (successful) EndAuth response <code>FlowToken</code> and <code>Ctx</code>; ConvergedTFA <code>canary</code></p></td></tr>
 <tr><td><p>resume (skip MFA registration)</p></td><td><p><code>flowtoken</code>, <code>canary</code></p></td><td><p>ConvergedProofUpRedirect <code>sFT</code> and <code>canary</code></p></td></tr>
 <tr><td><p>resume (skip MFA registration)</p></td><td><p><code>ctx</code></p></td><td><p>The <code>request</code> value that was posted to ProcessAuth (the ProofUp Auth Config carries no <code>sCtx</code>)</p></td></tr>
 <tr><td><p>token</p></td><td><p><code>code</code></p></td><td><p>The <code>code</code> on the final redirect <code>Location</code></p></td></tr>
</tbody></table>

Consequences for a conforming server: the authorize-time `sFT` MUST remain
valid across at least GetCredentialType, GetOneTimeCode and `login` (three
uses); and a SAS flow token MUST remain valid across repeated EndAuth
requests that present the BeginAuth value.

`canary` has the form `{base64}={n}:1:CANARY:{base64}`. The leading segment
(44 characters, ending in `=`) is constant for the whole session
(for example `gDmLyBKDxQx/…` on ConvergedSignIn, ConvergedTFA and
ConvergedProofUpRedirect); `n` differs per page (for example 7, 8 and 3
respectively) and the trailing segment changes on every issue. It contains `/`, `+` and `=` and MUST be
form-encoded when posted. Typical sizes: `sFT` 1322–1876 characters, `sCtx`
828–899, authorization `code` 1319–1329. Because EndAuth carries the flow token
and ctx as request headers, a receiving server or intermediary MUST accept
single header values of at least ~1.8 kB and total request headers of at least
~3 kB.

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
 <tr><td><p>User-Agent / Accept</p></td><td><p>A browser <code>User-Agent</code> string, and <code>*/*</code>. See [§2.20](#220-session-cookies-and-response-headers).</p></td></tr>
</tbody></table>

Request body (these are the keys ESTS expects; the capability flags are all
`true` except `isCookieBannerShown`, which is `false`):

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
account differs only in `PrefCredential: 1`, `RemoteNgcParams: null`, and the
absence of `HasRemoteNGC` and `IsSignupDisallowed`. The following `Credentials` members are present only when applicable
and are absent in the example: `HasAccessPass`, `HasFido`,
`FederationRedirectUrl`. Clients MUST treat an absent member as false/null.
`IsUnmanaged`, `DfpProperties`, `EstsProperties.DomainType`
(for example `3`), `Display` and `OtcNotAutoSent` are returned but do not
influence any later request.

The response sets `fpc` and `x-ms-gateway-slice` cookies and echoes
`client-request-id`; no `esctx*` cookie is issued by this call.

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
value MUST NOT be used to select a method.

__RemoteNgcParams__: When present, passwordless Authenticator MFA MAY proceed
via GetOneTimeCode and DeviceCodeStatus. `SessionIdentifier` is the device
code used in those calls. `Entropy` is the number-match value to display.

__FlowToken__: Updated flow token. Clients SHOULD use this value on subsequent
requests when provided.

__FidoParams__: When present, contains `AllowList` and optionally
`HasCrossDeviceCapablePasskey`.

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
 <tr><td><p>canary</p></td><td><p>`$Config.canary`</p></td></tr>
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
It is byte-identical to the `SessionIdentifier` returned by
GetCredentialType (`OldDeviceCode` names that session). `Entropy` is also unchanged. `DefaultType` changes from
`1` to `3`. The request carries `client-request-id` equal to the authorize
value and `canary` equal to `$Config.canary`; a `User-Agent` header is not required.
The first DeviceCodeStatus poll MAY follow GetOneTimeCode immediately.

`Entropy` is the number the user confirms in Authenticator when number
matching is enabled. `UserCode` MAY also be returned.

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
 <tr><td><p>canary</p></td><td><p>`$Config.canary`</p></td></tr>
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

Clients SHOULD poll on an interval on the order of several seconds until
`AuthorizationState` is non-zero or a local timeout elapses. No browser or
UI document execution is required for this poll.

Example timeline (offsets from the first poll): `0.00 s` state 0,
`5.11 s` state 0, `10.22 s` state 0, `15.33 s` state 2; the `login` POST follows
the approving poll immediately. The Auth Config on the sign-in page
advertises `iPollingTimeout: 300`, `iMaxPollErrors: 5` and
`iRemoteNgcPollingType: 2` ([§2.3.1](#231-common-fields)). The poll responses
carry `Set-Cookie` for `fpc` and `x-ms-gateway-slice` only.

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

##### 2.7.1.1.2 Response Body

On success ESTS returns `302` with a `Location` header of the form:

<pre><code>{redirect_uri}?code={authorization_code}&amp;session_state={guid}
</code></pre>

The `redirect_uri` matches the authorize request (for example
`ms-aadj-redir://auth/drs`).

The `302` response carries the full authenticated cookie set
([§2.20](#220-session-cookies-and-response-headers)), `Content-Type:
text/html; charset=utf-8`, and an `x-ms-clientdata` header. The form contains
exactly the eight fields in the table above: no `client_id` and no
`client-request-id`. The `flowToken`, `ctx` and `canary` values are the
authorize-time values ([§2.3.4](#234-state-token-lineage)), and `canary` is
`$Config.canary`, not `apiCanary`.

##### 2.7.1.1.3 Processing Details

The client MUST extract the `code` query parameter from `Location` and
exchange it per [§2.12](#212-authorization-code-token-exchange). No HTML
rendering is required.

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
 <tr><td><p>ctx</p></td><td><p>`$Config.sCtx`</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>`$Config.sFT`</p></td></tr>
 <tr><td><p>canary</p></td><td><p>`$Config.canary`</p></td></tr>
 <tr><td><p>client_id</p></td><td><p>Application client ID</p></td></tr>
 <tr><td><p>client-request-id</p></td><td><p>Correlation GUID</p></td></tr>
</tbody></table>

##### 2.8.1.1.2 Response Body

Outcomes:

1. __MFA required__: `200` HTML with `$Config.pgid` = `ConvergedTFA`,
   including `arrUserProofs`, `urlBeginAuth`, `urlEndAuth`, and
   `urlPost` pointing at `/common/SAS/ProcessAuth`.
2. __Authorization code__: `302` to `redirect_uri` with `code` when MFA is not
   required for this request.
3. __Other interrupts__: `200` HTML with `pgid` values such as
   `KmsiInterrupt`, `ConvergedChangePassword`, or `ConvergedConsent`.

ESTS MAY also return intermediate HTML pages that auto-submit a form
(“Working…”, “Click Submit to continue”). Clients MUST parse the form
`action` and hidden inputs and POST them until a terminal Auth Config or
redirect is obtained.

##### 2.8.1.1.3 Processing Details

After a ConvergedTFA response the client MUST parse the new `$Config` and
continue with SAS BeginAuth / EndAuth. Cookies from this response
(including authentication cookies such as `ESTSAUTH`) MUST be retained. In
the ConvergedTFA response already carries `ESTSAUTH`,
`ESTSAUTHPERSISTENT` and `ESTSAUTHLIGHT`, before MFA is satisfied
([§2.20](#220-session-cookies-and-response-headers)).

The form contains exactly the seven fields in the table above, in
the order `login`, `passwd`, `ctx`, `flowToken`, `canary`, `client_id`,
`client-request-id`. Unlike the Remote NGC `login`, a `client-request-id` is
posted and is a new GUID rather than the authorize value. The new
ConvergedTFA Auth Config contains `sessionId`, `sFT`, `sCtx`, `canary`
(`…=8:1:CANARY:…`), `arrUserProofs`, `urlBeginAuth`, `urlEndAuth`,
`urlPost` (ProcessAuth), `urlResume` (no query), `iMaxPollAttempts: 10`,
`iPollingInterval: 5000`, and no `sErrorCode`. Incorrect-password,
locked-account and similar failures are delivered as the same page type with
`sErrorCode` set ([§2.21](#221-error-signaling)).

## 2.9 SAS BeginAuth

### 2.9.1 BeginAuth

#### 2.9.1.1 POST

This method is transported by an HTTP POST to `$Config.urlBeginAuth`.

##### 2.9.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/common/SAS/BeginAuth
Content-Type: application/json; charset=utf-8
canary: {$Config.canary}
</code></pre>

Request body:

<pre><code class="lang-json">{
  "AuthMethodId": "PhoneAppNotification",
  "Method": "BeginAuth",
  "ctx": "{sCtx}",
  "flowToken": "{sFT}"
}
</code></pre>

__AuthMethodId__: One of the `arrUserProofs[].authMethodId` values.

__Method__: MUST be `BeginAuth`.

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

On `Success=true` the client MUST replace its working `flowToken` and `ctx`
with `FlowToken` and `Ctx` from this response for subsequent EndAuth and
ProcessAuth calls.

`Entropy` is the number-match value for PhoneAppNotification (for example `98`).
It is `0` in all later responses for the same session.

`SessionId` in this JSON is a SAS session identifier (a GUID, for example
`0186e637-…`) that stays constant across BeginAuth and every EndAuth
response. It is different from `$Config.sessionId` (for example `92ed25a4-…`), which is the
value EndAuth polling presents as `x-ms-sessionId`. `CorrelationId` equals the
authorize `client-request-id`. `Timestamp` is a UTC time of the form
`2026-11-04T17:48:12Z`.

On failure `Success` is `false`, `ResultValue` and `Message` describe the
condition, and `ErrCode` carries a numeric AADSTS code ([§2.21](#221-error-signaling)).
`Success: false` on BeginAuth is terminal for that method.

The request needs only `Content-Type` and `canary` headers (plus the usual
`Accept`, `Host` and `User-Agent`). The response sets `fpc` and `x-ms-gateway-slice` cookies.

## 2.10 SAS EndAuth

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
 <tr><td><p>x-ms-sessionId</p></td><td><p>`$Config.sessionId` from ConvergedTFA</p></td></tr>
 <tr><td><p>x-ms-flowToken</p></td><td><p>Current flow token (from BeginAuth)</p></td></tr>
 <tr><td><p>x-ms-ctx</p></td><td><p>Current ctx (from BeginAuth)</p></td></tr>
 <tr><td><p>Cookie</p></td><td><p>ESTS cookies</p></td></tr>
</tbody></table>

`pollCount` is a 1-based counter of poll attempts.

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

`MobileAppAuthDetails` is present (non-null) only on the approving response.
It contains `PolicyResults` entries; the entry with `Feature: 2`
reported `NumberMatchCorrectNumberEntered`, which is how the number-match
outcome is surfaced. `AuthAppState` is an opaque base64 string. These members
are informational: neither is posted in any later request.

##### 2.10.1.1.3 Processing Details

If `Success` is false and `Retry` is true, the client MUST wait approximately
`iPollingInterval` milliseconds and poll again with an incremented
`pollCount`, until `iMaxPollAttempts` is exceeded.

If `Success` is true, the client MUST update `flowToken` / `ctx` from the
response and continue to ProcessAuth.

If `Success` is false and `Retry` is false, the challenge has failed and
`ErrCode` carries the AADSTS code, for example `500121` (the user did not
complete the MFA prompt) ([§2.21](#221-error-signaling)).

Example timeline: BeginAuth completes at `t0`; the first poll is sent at
`t0 + 0.4 s` and returns pending; later polls follow at about 5.2 s
intervals (5.1–5.3 s); the approving poll returns `Success: true`; ProcessAuth
is posted under one second later. Successive polls MAY be served by
different ESTS nodes in different datacenters (`x-ms-ests-server`: for
example WUS3, EUS, SCUS), so flow state is carried entirely by the tokens and
cookies, not by node affinity. Each poll carries `x-ms-flowToken` (about 1.8
kB) and `x-ms-ctx` (about 0.9 kB) as headers and an empty body.

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
`canary: {$Config.canary}`.

The response schema matches [§2.10.1.1.2](#210112-response-body). On
`Success=true` the client continues to ProcessAuth.

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
 <tr><td><p>request</p></td><td><p>Current ctx (EndAuth / BeginAuth Ctx)</p></td></tr>
 <tr><td><p>mfaAuthMethod</p></td><td><p>Auth method id. <code>ConsolidatedTelephony</code> is posted as
 <code>OneWaySMS</code>.</p></td></tr>
 <tr><td><p>login</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current flow token</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Canary from ConvergedTFA `$Config`</p></td></tr>
</tbody></table>

##### 2.11.1.1.2 Response Body

Outcomes:

1. __Redirect with code__: `302` `Location` containing `code` (flow complete).
2. __MFA registration interrupt__: `200` HTML with
   `pgid=ConvergedProofUpRedirect`, `sErrorCode` of `50203`, and
   `urlSkipMfaRegistration` when postponement is allowed.
3. __Intermediate auto-submit HTML__: same handling as
   [§2.8.1.1.2](#28112-response-body).

##### 2.11.1.1.3 Processing Details

When `urlSkipMfaRegistration` is present, the client MAY POST that endpoint
per [§2.13](#213-skip-mfa-registration-resume) to complete authorization
without registering an additional MFA method.

The ProcessAuth form contains exactly `request`, `mfaAuthMethod`,
`login`, `flowToken`, `canary` in that order; the `canary` is the ConvergedTFA
value (`n:1`). The `200` response sets `ESTSAUTH`, `ESTSAUTHPERSISTENT`,
`ESTSAUTHLIGHT`, `buid`, `esctx`, a new `esctx-{id}`, `fpc` and
`x-ms-gateway-slice`, and clears the previous `esctx-{id}` cookie. It
carries no `x-ms-clientdata`. The ConvergedProofUpRedirect Auth Config that
follows contains a new `sFT`, a new `canary`, no `sCtx`, and
`sessionId` equal to the response's own request id.

## 2.12 Authorization Code Token Exchange

### 2.12.1 token

#### 2.12.1.1 POST

This method is transported by an HTTP POST.

##### 2.12.1.1.1 Request

<pre><code>POST https://login.microsoftonline.com/{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>client_id</p></td><td><p>Application client ID</p></td></tr>
 <tr><td><p>grant_type</p></td><td><p>authorization_code</p></td></tr>
 <tr><td><p>code</p></td><td><p>Authorization code from the final redirect</p></td></tr>
 <tr><td><p>redirect_uri</p></td><td><p>Exact redirect_uri from the authorize request</p></td></tr>
</tbody></table>

##### 2.12.1.1.2 Response Body

<pre><code class="lang-json">{
  "token_type": "Bearer",
  "scope": "mdm_delegation",
  "expires_in": "5115",
  "ext_expires_in": "5115",
  "expires_on": "1793819646",
  "not_before": "1793814230",
  "resource": "https://enrollment.manage.microsoft.com/",
  "access_token": "string",
  "refresh_token": "string",
  "id_token": "string"
}
</code></pre>

##### 2.12.1.1.3 Processing Details

`redirect_uri` MUST byte-for-byte match the authorize request. The resulting
tokens reflect the resource/scopes of that authorize request. MFA satisfaction
is represented in token claims; this exchange itself is the standard OAuth 2.0
authorization-code grant, and needs only the four listed fields (no
PKCE, no secret, no `resource`).

The response is `200` with `Content-Type: application/json;
charset=utf-8`, `Cache-Control: no-store, no-cache`, and
`x-ms-clientdata: e|||microsoftonline.com|none`. Token facts for a v1
access token issued after password plus PhoneAppNotification MFA:

<table class="protocol-table"><thead>
  <tr><th><p>Item</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p><code>expires_in</code></p></td><td><p><code>"5115"</code> (string). Equal to <code>exp</code> minus the server time of the response; the access token lifetime from <code>nbf</code> to <code>exp</code> is, for example, 5416 s.</p></td></tr>
 <tr><td><p><code>iat</code> / <code>nbf</code></p></td><td><p>Both 300 s earlier than the response time (clock-skew allowance).</p></td></tr>
 <tr><td><p>Access token header</p></td><td><p><code>typ: JWT</code>, <code>alg: RS256</code>, <code>x5t</code> and <code>kid</code> (equal).</p></td></tr>
 <tr><td><p>Access token claims</p></td><td><p><code>aud</code> (resource URI), <code>iss</code> (<code>https://sts.windows.net/{tid}/</code>), <code>iat</code>, <code>nbf</code>, <code>exp</code>, <code>acr: "1"</code>, <code>amr: ["pwd","mfa"]</code>, <code>appid</code> (client id), <code>appidacr: "0"</code>, <code>idtyp: "user"</code>, <code>ipaddr</code>, <code>name</code>, <code>oid</code>, <code>puid</code>, <code>rh</code>, <code>scp: "mdm_delegation"</code>, <code>sid</code>, <code>sub</code>, <code>tid</code>, <code>unique_name</code>, <code>upn</code>, <code>uti</code>, <code>ver: "1.0"</code>, <code>wids</code>, <code>xms_act_fct</code>, <code>xms_aud_guid</code>, <code>xms_ftd</code>, <code>xms_idrel</code>, <code>xms_sub_fct</code>, <code>aio</code>.</p></td></tr>
 <tr><td><p>ID token claims</p></td><td><p><code>aud</code> (client id), <code>iss</code>, <code>iat</code>, <code>nbf</code>, <code>exp</code> (3900 s after <code>iat</code>), <code>amr: ["pwd","mfa"]</code>, <code>idtyp</code>, <code>ipaddr</code>, <code>name</code>, <code>oid</code>, <code>puid</code>, <code>rh</code>, <code>sub</code>, <code>tenant_region_scope</code>, <code>tid</code>, <code>unique_name</code>, <code>upn</code>, <code>uti</code>, <code>ver: "1.0"</code>, <code>xms_idrel</code>, <code>aio</code>. The <code>sub</code> of the ID token differs from the <code>sub</code> of the access token (pairwise).</p></td></tr>
 <tr><td><p>Authentication methods claim</p></td><td><p><code>amr</code> carries <code>pwd</code> and <code>mfa</code> after a password plus PhoneAppNotification sign-in.</p></td></tr>
 <tr><td><p>Refresh token</p></td><td><p>Opaque string beginning <code>1.</code> (about 1.5 kB).</p></td></tr>
 <tr><td><p>Redirect <code>session_state</code></p></td><td><p>Equal to the <code>sid</code> claim of the access token.</p></td></tr>
</tbody></table>

Errors at this endpoint use the standard OAuth 2.0 JSON shape
(`error`, `error_description`, `error_codes`, `timestamp`, `trace_id`,
`correlation_id`); `error_description` begins `AADSTS{code}:`.

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
 <tr><td><p>flowtoken</p></td><td><p>Flow token from the ProofUp Auth Config (`sFT`). Note the lowercase
 field name.</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Current ctx</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Canary from the ProofUp Auth Config</p></td></tr>
</tbody></table>

##### 2.13.1.1.2 Response Body

On success: `302` with `Location` containing `code` and `session_state`,
suitable for [§2.12](#212-authorization-code-token-exchange). The response sets the same authenticated cookie set as the code-issuing
Remote NGC `login` response ([§2.7.1.1.2](#27112-response-body)), plus `CCState` and `SignInStateCookie`, and returns
`x-ms-clientdata: e|||microsoftonline.com|none`.

The ProofUp page that offers this URL does not carry `sCtx`; the `ctx` field
reuses the value posted to ProcessAuth. The ProofUp Auth Config's own `urlPost`
points to a separate registration host and is not part of this protocol.
Skipping succeeds with `sErrorCode: 50203` and no
`iRemainingDaysToSkipMfaRegistration` member on the ProofUp page.

## 2.14 FIDO Authentication

FIDO may be offered passwordlessly (via GetCredentialType `FidoParams`) or
after password login (via ConvergedTFA `arrUserProofs` entry `FidoKey` /
`arrFidoAllowList`). Both use the same ESTS HTTP surface: a challenge
bootstrap POST to `urlFidoLogin`, then an assertion POST to `urlPost`.

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
 <tr><td><p>allowedIdentities</p></td><td><p>`$Config.iAllowedIdentities` as decimal string</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current flow token (`sFT`)</p></td></tr>
 <tr><td><p>serverChallenge</p></td><td><p>Current flow token (`sFT`)</p></td></tr>
 <tr><td><p>postBackUrl</p></td><td><p>Current <code>urlPost</code></p></td></tr>
 <tr><td><p>postBackUrlAad</p></td><td><p>Current <code>urlPost</code></p></td></tr>
 <tr><td><p>cancelUrl</p></td><td><p>Current <code>urlResume</code></p></td></tr>
 <tr><td><p>resumeUrl</p></td><td><p>Current <code>urlResume</code></p></td></tr>
 <tr><td><p>correlationId</p></td><td><p>Client request / correlation GUID</p></td></tr>
 <tr><td><p>credentialsJson</p></td><td><p>First entry of the FIDO allow-list
 (`FidoParams.AllowList[0]` or `arrFidoAllowList[0]`)</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Current <code>sCtx</code></p></td></tr>
 <tr><td><p>username</p></td><td><p>User principal name</p></td></tr>
 <tr><td><p>loginCanary</p></td><td><p>`$Config.canary`</p></td></tr>
</tbody></table>

##### 2.14.1.1.2 Response Body

`200` HTML containing a new Auth Config. Required fields for completion:

- `sFidoChallenge` — challenge material for the local authenticator
- `sCrossDomainCanary` — posted later as `lmcCanary`
- `sessionId`, `sFT`, `sCtx`, `canary`, `urlPost`

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
`$Config.fIsPasskeySupportEnabled`) indicates a cross-device passkey. Platform
passkey UX is outside this HTTP protocol; the ESTS posts below are unchanged.

### 2.14.2 FIDO Assertion Completion

#### 2.14.2.1 POST

##### 2.14.2.1.1 Request

<pre><code>POST {urlPost}
Content-Type: application/x-www-form-urlencoded
</code></pre>

Form fields:

<table class="protocol-table"><thead>
  <tr><th><p>Field</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p>type</p></td><td><p><code>23</code></p></td></tr>
 <tr><td><p>ps</p></td><td><p><code>23</code></p></td></tr>
 <tr><td><p>assertion</p></td><td><p>FIDO/WebAuthn assertion payload</p></td></tr>
 <tr><td><p>lmcCanary</p></td><td><p>`sCrossDomainCanary` from the FIDO Auth Config</p></td></tr>
 <tr><td><p>hpgrequestid</p></td><td><p>`sessionId`</p></td></tr>
 <tr><td><p>ctx</p></td><td><p>Current ctx</p></td></tr>
 <tr><td><p>canary</p></td><td><p>Current canary</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current flow token</p></td></tr>
</tbody></table>

##### 2.14.2.1.2 Response Body

Success yields either:

1. `302` `Location` containing `code`, or
2. `200` HTML that includes an anchor whose `href` carries `code` (or
   `error_description`) as query parameters. Clients MUST parse that href
   when `Location` is absent.

Intermediate auto-submit HTML MAY appear ([§2.18](#218-intermediate-auto-submit-html)).

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
 <tr><td><p>ctx</p></td><td><p>Current sCtx</p></td></tr>
 <tr><td><p>flowToken</p></td><td><p>Current sFT</p></td></tr>
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

When ProofUp cannot be postponed (`urlSkipMfaRegistration` absent and no
remaining skip days), the skip-resume API in [§2.13](#213-skip-mfa-registration-resume)
is the documented non-registration escape hatch when ESTS advertises it;
otherwise MFA method registration must be completed out of band.

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

Success is indicated by HTTP success status; the client may then restart
interactive authentication with the new password.

Prior to SSPR begin, the password-change Auth Config itself is typically
reached by posting username/password (and canary/ctx/flowToken) to the
sign-in `urlPost`, identical to [§2.8](#28-login-password-submission).

Further details: the authorize request that
begins a password-change sign-in omits `amr_values=ngcmfa`; the JSON posts
carry no `canary` header (the canary appears only in the final body); the
URLs `urlAsyncSsprBegin`, `urlAsyncSsprPoll` and `urlPost` MAY be
root-relative (beginning `/`), in which case they resolve against the scheme
and host of the authorize URL ([§2.22](#222-authorization-response-delivery-forms)); polling occurs
about once per second; and success is signaled by an HTTP success status
on the final post.

## 2.18 Intermediate Auto-Submit HTML

ESTS intermittently returns `200` HTML pages whose body instructs the user
agent to continue (for example text containing “Working…”, “Click Submit to
continue”, “Click here to finish the authorization process”, or a form with
`<input type="submit">`).

Processing rules:

1. Parse the first HTML `form`.
2. Read the form `action` as the next POST URL.
3. Collect all `input` elements that have both `name` and `value`.
4. `POST` `application/x-www-form-urlencoded` to the action URL with those
   fields.
5. Repeat until the response is a redirect with `code`, an Auth Config page
   that is not an auto-submit interstitial, or an error.

Clients MUST NOT require a full browser layout engine; HTML form parsing is
sufficient.

Interstitials are detected by a substring match on the response body for
any of `Click Submit to continue`, `Working...`,
`Click here to finish the authorization process`, or `<input type="submit"`.
Only inputs carrying both `name` and `value` attributes are posted. The form
is posted without any ESTS-specific headers.

## 2.19 OAuth 2.0 Device Authorization Grant

This grant is a separate interactive MFA channel. The user authenticates
(including MFA) in a browser at a verification URI while the client polls a
token endpoint. It does not use `$Config`, SAS, or GetCredentialType.

### 2.19.1 Organizational Device Code

#### 2.19.1.1 Device Code Request

<pre><code>POST https://login.microsoftonline.com/{tenant|common}/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&amp;scope={urlencoded-scopes}
</code></pre>

`scope` typically includes `openid profile offline_access` plus resource
scopes. Including `{azure-portal-app-id}/.default` (application ID
`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`) is used when the client needs the
resulting tokens to carry MFA context suitable for later exchange.

The request carries `Accept: application/json`. `openid profile
offline_access` is sent ahead of any additional scopes.

Response JSON (RFC 8628 Device Authorization Response) includes
`device_code`, `user_code`, `verification_uri`, `expires_in`, optional
`interval`, and `message`. `verification_uri_complete` is not
returned. Failures use the token-endpoint error shape ([§2.21](#221-error-signaling)).

#### 2.19.1.2 Device Code Token Poll

<pre><code>POST https://login.microsoftonline.com/{tenant|common}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&amp;grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&amp;device_code={device_code}
</code></pre>

Pending authorization returns an HTTP error response (JSON,
`error: "authorization_pending"`) whose `error_codes` include `70016`.
Success returns a v2.0 token response (numeric `expires_in`; `refresh_token`
because `offline_access` was requested). The access token's identity
(`upn` / `preferred_username`) is what a client compares to the intended user,
since any user can complete the verification page.

The client MAY redeem the refresh token for a different resource:

<pre><code>POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded
Accept: application/json

client_id={client_id}&amp;scope=openid%20profile%20offline_access%20{resource}%2F.default&amp;grant_type=refresh_token&amp;refresh_token={refresh_token}&amp;client_info=1
</code></pre>

The same endpoint also accepts
`grant_type=password` with `username`, `password` and `client_info=1`;
that grant is non-interactive and therefore cannot satisfy an MFA
requirement (the server returns an AADSTS error such as `50076`,
[§2.21](#221-error-signaling)).

### 2.19.2 Consumers (Personal Account) Device Code

For `IfExistsResult == 5` personal Microsoft accounts:

<pre><code>POST https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode
POST https://login.microsoftonline.com/consumers/oauth2/v2.0/token
</code></pre>

Request/response shapes match [§2.19.1](#2191-organizational-device-code).
The verification experience is hosted at a consumers URI (commonly under
`www.microsoft.com/link`), and the `verification_uri` host distinguishes the personal flow from the organizational one. Personal accounts
cannot be issued a token for the device-enrollment resource
(`enrollment.manage.microsoft.com`) through this route.

## 2.20 Session Cookies and Response Headers

### 2.20.1 Cookies

All cookies are on `login.microsoftonline.com` with `Secure` and
`SameSite=None`. A client MUST keep a cookie jar, MUST return the cookies on
every later request to the host, and MUST honor deletion: a `Set-Cookie`
with an empty value and a past `expires` removes the named cookie.

<table class="protocol-table"><thead>
  <tr><th><p>Cookie</p></th><th><p>Attributes</p></th><th><p>Set by</p></th><th><p>Notes</p></th></tr>
</thead><tbody>
 <tr><td><p><code>buid</code></p></td><td><p>host-only, <code>HttpOnly</code>, expires +30 days</p></td><td><p>authorize; every authenticating step</p></td><td><p>Value changes per issue.</p></td></tr>
 <tr><td><p><code>esctx</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code></p></td><td><p>authorize; each authenticating step</p></td><td><p>Page/request context cookie.</p></td></tr>
 <tr><td><p><code>esctx-{id}</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code>; <code>{id}</code> is an 11-character suffix</p></td><td><p>authorize; each authenticating step</p></td><td><p>The suffix is new on each issue. Each authenticating response also deletes the previous <code>esctx-{id}</code>. For example: <code>esctx-tudMxTqay0</code> (authorize), deleted at password login which issued <code>esctx-V4Ifm9r8WpE</code>, deleted at ProcessAuth which issued <code>esctx-9ldDmB4UAWk</code>, deleted at resume with no replacement.</p></td></tr>
 <tr><td><p><code>fpc</code></p></td><td><p>host-only, <code>HttpOnly</code>, expires +30 days from each issue</p></td><td><p>every ESTS response</p></td><td><p>The value is extended on each authenticating step by appending segments (the value seen at authorize is a prefix of every later value).</p></td></tr>
 <tr><td><p><code>x-ms-gateway-slice</code>, <code>stsservicecookie</code></p></td><td><p><code>httponly</code>; value <code>estsfd</code></p></td><td><p>authorize (<code>stsservicecookie</code> only here); GetCredentialType and every later response</p></td><td><p>Routing hint.</p></td></tr>
 <tr><td><p><code>ESTSAUTHPERSISTENT</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code>, expires +90 days</p></td><td><p>the first authenticating response: Remote NGC <code>login</code>; password <code>login</code>; re-issued by ProcessAuth and resume</p></td><td><p>Present on a ConvergedTFA response, i.e. before MFA is satisfied.</p></td></tr>
 <tr><td><p><code>ESTSAUTH</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code>, session cookie</p></td><td><p>same responses as <code>ESTSAUTHPERSISTENT</code></p></td><td><p></p></td></tr>
 <tr><td><p><code>ESTSAUTHLIGHT</code></p></td><td><p>host-only, not <code>HttpOnly</code>, session cookie; value <code>+{guid}</code></p></td><td><p>same responses</p></td><td><p>The GUID can equal the redirect <code>session_state</code> (Remote NGC login); after password plus SAS MFA only its first segment matched <code>session_state</code> / <code>sid</code>.</p></td></tr>
 <tr><td><p><code>CCState</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code>, expires +10 days</p></td><td><p>responses that issue the authorization code (login, resume)</p></td><td><p></p></td></tr>
 <tr><td><p><code>SignInStateCookie</code></p></td><td><p>domain <code>.login.microsoftonline.com</code>, <code>HttpOnly</code>, session cookie</p></td><td><p>responses that issue the authorization code</p></td><td><p></p></td></tr>
</tbody></table>

The token endpoint response sets only `fpc` and `x-ms-gateway-slice`. Which
individual cookies ESTS requires on each request is not specified; a client
SHOULD send the whole jar on every request after authorize.

### 2.20.2 Request Headers

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Where</p></th><th><p>Value</p></th></tr>
</thead><tbody>
 <tr><td><p><code>Host</code></p></td><td><p>all</p></td><td><p><code>login.microsoftonline.com</code> (<code>odc.officeapps.live.com</code> for federation discovery)</p></td></tr>
 <tr><td><p><code>Accept</code></p></td><td><p>all</p></td><td><p><code>*/*</code></p></td></tr>
 <tr><td><p><code>Content-Type</code></p></td><td><p>POST</p></td><td><p><code>application/json; charset=UTF-8</code> (GetCredentialType, GetOneTimeCode); <code>application/json</code> (DeviceCodeStatus); <code>application/json; charset=utf-8</code> (BeginAuth, EndAuth POST); <code>application/x-www-form-urlencoded</code> (login, ProcessAuth, resume, token, FIDO, SAS form posts)</p></td></tr>
 <tr><td><p><code>client-request-id</code></p></td><td><p>GetCredentialType, GetOneTimeCode</p></td><td><p>The authorize correlation GUID</p></td></tr>
 <tr><td><p><code>canary</code></p></td><td><p>GetOneTimeCode, DeviceCodeStatus, BeginAuth, EndAuth POST</p></td><td><p><code>$Config.canary</code> of the page being answered</p></td></tr>
 <tr><td><p><code>x-ms-sessionId</code>, <code>x-ms-flowToken</code>, <code>x-ms-ctx</code></p></td><td><p>EndAuth GET</p></td><td><p>[§2.10](#210-sas-endauth)</p></td></tr>
 <tr><td><p><code>User-Agent</code></p></td><td><p>all</p></td><td><p>A browser string (for example Firefox 131) on authorize, GetCredentialType, DeviceCodeStatus, BeginAuth and password <code>login</code>; EndAuth, ProcessAuth, resume and token accept a non-browser product token. FIDO capability gating depends on this header ([§2.14.1.1.3](#214113-processing-details)).</p></td></tr>
</tbody></table>

### 2.20.3 Response Headers

<table class="protocol-table"><thead>
  <tr><th><p>Header</p></th><th><p>Where</p></th><th><p>Meaning</p></th></tr>
</thead><tbody>
 <tr><td><p><code>client-request-id</code></p></td><td><p>GetCredentialType, GetOneTimeCode</p></td><td><p>Echo of the request header.</p></td></tr>
 <tr><td><p><code>x-ms-request-id</code></p></td><td><p>all ESTS responses</p></td><td><p>Server trace GUID. Equal to the <code>sessionId</code> of the Auth Config the response carries.</p></td></tr>
 <tr><td><p><code>x-ms-ests-server</code></p></td><td><p>all</p></td><td><p>Build, datacenter and slice, for example <code>2.1.25449.3 - WUS3 ProdSlices</code>. Consecutive polls MAY be answered from different datacenters (for example WUS3, EUS, SCUS, NCUS).</p></td></tr>
 <tr><td><p><code>x-ms-srs</code></p></td><td><p>all</p></td><td><p><code>1.P</code></p></td></tr>
 <tr><td><p><code>x-ms-clientdata</code></p></td><td><p>Remote NGC login redirect; resume and token</p></td><td><p><code>e|||microsoftonline.com|none</code></p></td></tr>
 <tr><td><p><code>Cache-Control</code></p></td><td><p>JSON, HTML</p></td><td><p><code>no-store, no-cache</code>; <code>Expires: -1</code>; <code>Pragma: no-cache</code> on HTML</p></td></tr>
 <tr><td><p><code>Content-Security-Policy-Report-Only</code></p></td><td><p>all</p></td><td><p>Contains a per-response script <code>nonce</code>; on HTML pages it equals the <code>nonce</code> attribute of the <code>$Config</code> script element.</p></td></tr>
 <tr><td><p><code>Location</code></p></td><td><p>302</p></td><td><p>Authorization-code redirect, [§2.22](#222-authorization-response-delivery-forms).</p></td></tr>
</tbody></table>

## 2.21 Error Signaling

ESTS reports failures in four places. A client MUST check all four.

<table class="protocol-table"><thead>
  <tr><th><p>Channel</p></th><th><p>Shape</p></th></tr>
</thead><tbody>
 <tr><td><p>Auth Config on an HTML <code>200</code></p></td><td><p><code>sErrorCode</code> (string) or <code>iErrorCode</code> (number), <code>sErrTxt</code> and/or <code>strServiceExceptionMessage</code>, and <code>arrValErrs</code>. <code>pgid</code> stays on the page that reports the error. <code>sErrorCode: "50058"</code> on the first ConvergedSignIn page is NOT an error.</p></td></tr>
 <tr><td><p>SAS JSON</p></td><td><p><code>Success: false</code>, <code>Retry: false</code>, <code>ResultValue</code>, <code>Message</code>, <code>ErrCode</code> (numeric AADSTS code).</p></td></tr>
 <tr><td><p>Authorization redirect</p></td><td><p><code>Location</code> with <code>error</code> and <code>error_description</code>; <code>error_description</code> begins <code>AADSTS{code}:</code> and is followed by <code>Trace ID</code>, <code>Correlation ID</code> and <code>Timestamp</code> lines.</p></td></tr>
 <tr><td><p>Token / device endpoint JSON</p></td><td><p><code>error</code>, <code>error_description</code>, <code>error_codes</code> [array], <code>timestamp</code>, <code>trace_id</code>, <code>correlation_id</code>.</p></td></tr>
</tbody></table>

AADSTS codes relevant to this protocol, with the catalog meaning:

<table class="protocol-table"><thead>
  <tr><th><p>Code</p></th><th><p>Name / meaning</p></th></tr>
</thead><tbody>
 <tr><td><p>50058</p></td><td><p>UserInformationNotProvided; session information is insufficient, expected on the initial page.</p></td></tr>
 <tr><td><p>50203</p></td><td><p>The user has not registered the authenticator app and must register or snooze. With <code>urlSkipMfaRegistration</code> present this is the ProofUp interrupt in [§2.13](#213-skip-mfa-registration-resume).</p></td></tr>
 <tr><td><p>50072</p></td><td><p>UserStrongAuthEnrollmentRequiredInterrupt; user must enroll a second factor interactively.</p></td></tr>
 <tr><td><p>50079</p></td><td><p>UserStrongAuthEnrollmentRequired; MFA required and no method registered.</p></td></tr>
 <tr><td><p>50076</p></td><td><p>UserStrongAuthClientAuthNRequired; MFA required (for example by Conditional Access); retry with a new authorize request.</p></td></tr>
 <tr><td><p>50074</p></td><td><p>UserStrongAuthClientAuthNRequiredInterrupt; strong authentication required and the MFA challenge was not passed.</p></td></tr>
 <tr><td><p>500121</p></td><td><p>Strong authentication failed: the user did not complete the MFA prompt (denied, timed out, or setup issue).</p></td></tr>
 <tr><td><p>50087</p></td><td><p>SasRetryableError; transient failure in strong authentication; retry.</p></td></tr>
 <tr><td><p>50089</p></td><td><p>Flow token expired.</p></td></tr>
 <tr><td><p>50126</p></td><td><p>InvalidUserNameOrPassword.</p></td></tr>
 <tr><td><p>50053</p></td><td><p>IdsLocked; account locked or request blocked by IP reputation.</p></td></tr>
 <tr><td><p>50055</p></td><td><p>Password expired (password change interrupt).</p></td></tr>
 <tr><td><p>50140</p></td><td><p>KmsiInterrupt; the "keep me signed in" interrupt.</p></td></tr>
 <tr><td><p>16000</p></td><td><p>InteractionRequired.</p></td></tr>
 <tr><td><p>53003</p></td><td><p>Blocked by Conditional Access.</p></td></tr>
 <tr><td><p>65001</p></td><td><p>Consent required (<code>DelegationDoesNotExist</code>).</p></td></tr>
 <tr><td><p>54005</p></td><td><p>Authorization code already redeemed.</p></td></tr>
 <tr><td><p>70016</p></td><td><p>AuthorizationPending (device flow; keep polling).</p></td></tr>
 <tr><td><p>70011</p></td><td><p>InvalidScope.</p></td></tr>
 <tr><td><p>700016</p></td><td><p>Application not found in the tenant (client id does not match).</p></td></tr>
</tbody></table>

Codes `50203`, `16000` and `50072` indicate that the browserless
password/SAS route cannot complete without registration or an interaction the
route does not provide; a client falls back to the device authorization grant
([§2.19](#219-oauth-20-device-authorization-grant)) for those codes and for
federated identities (`Credentials.FederationRedirectUrl`).

## 2.22 Authorization Response Delivery Forms

An authorization code is delivered in one of four forms. A client MUST accept
all of them after every POST that can complete the flow (password `login`,
Remote NGC `login`, ProcessAuth, `resume`, FIDO assertion, Access Pass,
`LoginOptions=1`) and after a silent authorize request:

<table class="protocol-table"><thead>
  <tr><th><p>Form</p></th><th><p>Detection</p></th><th><p>Extraction</p></th></tr>
</thead><tbody>
 <tr><td><p>302 Location</p></td><td><p>HTTP <code>302</code> with <code>Location</code></p></td><td><p>Parse the URL; read <code>code</code> (and <code>session_state</code>). If <code>error_description</code> is present it is an error ([§2.21](#221-error-signaling)). The scheme may be custom (<code>ms-aadj-redir://</code>, <code>companyportal://</code>).</p></td></tr>
 <tr><td><p>302 with HTML anchor</p></td><td><p><code>302</code> whose body is an HTML page with an <code><a href></code></p></td><td><p>Percent-decode the first anchor <code>href</code>, parse it as a URL, read <code>code</code>.</p></td></tr>
 <tr><td><p>200 JavaScript redirect</p></td><td><p><code>200</code> HTML containing <code>document.location.replace("{url}")</code></p></td><td><p>Replace <code>\u0026</code> with <code>&</code> in <code>{url}</code>, parse, read <code>code</code> or <code>error_description</code>.</p></td></tr>
 <tr><td><p>200 with FIDO anchor</p></td><td><p><code>200</code> HTML from the FIDO assertion post</p></td><td><p>Parse the anchor <code>href</code> for <code>code</code> or <code>error_description</code>.</p></td></tr>
</tbody></table>

If none of the forms matches, the body is re-parsed as an Auth Config: an
error, `ConvergedChangePassword`, `ConvergedConsent`, `KmsiInterrupt` (a `200`
with no redirect) or `ConvergedProofUpRedirect` indicates an interrupt.

Auth Config URLs (`urlPost`, `urlAsyncSsprBegin`, ...) MAY be root-relative.
A root-relative value is resolved against the scheme and host of the
authorize URL, not against the tenant path. Values are typically absolute.

## 2.23 Timing Summary

All values are typical intervals, not server-mandated limits unless stated.

<table class="protocol-table"><thead>
  <tr><th><p>Interval</p></th><th><p>Typical</p></th></tr>
</thead><tbody>
 <tr><td><p>authorize → GetCredentialType</p></td><td><p>about 0.3 s</p></td></tr>
 <tr><td><p>GetCredentialType → GetOneTimeCode</p></td><td><p>user-driven (about 1.5 s)</p></td></tr>
 <tr><td><p>GetOneTimeCode → first DeviceCodeStatus</p></td><td><p>under 0.2 s</p></td></tr>
 <tr><td><p>DeviceCodeStatus poll spacing</p></td><td><p>about 5.1 s</p></td></tr>
 <tr><td><p>approving DeviceCodeStatus → login</p></td><td><p>under 0.2 s</p></td></tr>
 <tr><td><p>password login → BeginAuth</p></td><td><p>about 0.25 s</p></td></tr>
 <tr><td><p>BeginAuth → first EndAuth</p></td><td><p>about 0.4 s</p></td></tr>
 <tr><td><p>EndAuth poll spacing</p></td><td><p>5.1–5.3 s</p></td></tr>
 <tr><td><p>approving EndAuth → ProcessAuth</p></td><td><p>under 1 s</p></td></tr>
 <tr><td><p>ProcessAuth → resume → token</p></td><td><p>about 0.2 s each</p></td></tr>
 <tr><td><p>Auth Config advertised</p></td><td><p><code>iPollingInterval</code> 5000 (ConvergedTFA), <code>iMaxPollAttempts</code> 10, <code>iPollingTimeout</code> 300 (ConvergedSignIn)</p></td></tr>
 <tr><td><p>Access token lifetime</p></td><td><p><code>nbf</code> to <code>exp</code> about 5400 s; ID token about 3900 s</p></td></tr>
 <tr><td><p>Authorization code lifetime</p></td><td><p>about 1 minute</p></td></tr>
 <tr><td><p><code>fpc</code> / <code>buid</code> cookies</p></td><td><p>30 days; <code>ESTSAUTHPERSISTENT</code> 90 days; <code>CCState</code> 10 days</p></td></tr>
</tbody></table>

# 3 Protocol Examples (Non-Normative)

Examples below omit cookie headers and truncate opaque tokens.

## 3.1 Passwordless Remote NGC

### 3.1.1 Federation Provider

#### Request

<pre><code>GET /odc/v2.1/federationProvider?domain=contoso.com HTTP/1.1
Host: odc.officeapps.live.com
Accept: */*
</code></pre>

#### Response

<pre><code>HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"environment":"Global","tenantId":"6973bb37-65f8-440e-b39e-dd57da64f6cf",
 "authority_host":"login.microsoftonline.com","graph":"https://graph.microsoft.com",
 "endpoint":[{"type":"OrgId",
   "authentication_endpoint":"https://login.microsoftonline.com/common/oauth2/authorize",
   "token_endpoint":"https://login.microsoftonline.com/common/oauth2/token"},"..."]}
</code></pre>

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
 "FlowToken":"...","Ctx":"...","Entropy":98,"Retry":false,"ErrCode":0,...}
</code></pre>

### 3.2.3 EndAuth poll → ProcessAuth → token

Pending polls return `"Success":false,"Retry":true,"ResultValue":"AuthenticationPending"`.
The approving poll returns `"Success":true`. ProcessAuth is then posted:

<pre><code>request=...&amp;mfaAuthMethod=PhoneAppNotification&amp;login=user%40contoso.com&amp;flowToken=...&amp;canary=...
</code></pre>

If a ProofUp interrupt is returned, POST
`/{tenant}/resume?skipmfaregistration=1` with `flowtoken`, `ctx`, and
`canary`. The final `302` Location yields `code`, exchanged at:

<pre><code>POST /{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=...&amp;grant_type=authorization_code&amp;code=...&amp;redirect_uri=ms-aadj-redir%3A%2F%2Fauth%2Fdrs
</code></pre>

## 3.3 SAS PhoneAppOTP

After ConvergedTFA and BeginAuth with `AuthMethodId=PhoneAppOTP`:

<pre><code>POST /common/SAS/EndAuth HTTP/1.1
Content-Type: application/json; charset=utf-8
canary: ...

{"AdditionalAuthData":"123456","AuthMethodId":"PhoneAppOTP",
 "SessionId":"...","FlowToken":"...","Ctx":"...","Method":"EndAuth"}
</code></pre>

Then ProcessAuth with `mfaAuthMethod=PhoneAppOTP`.

## 3.4 SAS ConsolidatedTelephony → ProcessAuth mapping

BeginAuth / EndAuth use `AuthMethodId=ConsolidatedTelephony`. ProcessAuth
posts `mfaAuthMethod=OneWaySMS`.

## 3.5 FIDO Assertion Completion

After `urlFidoLogin` returns `sFidoChallenge` / `sCrossDomainCanary`:

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

## 3.7 Device Authorization Grant

<pre><code>POST /{tenant}/oauth2/v2.0/devicecode
client_id=...&amp;scope=openid%20profile%20offline_access%20...

POST /{tenant}/oauth2/v2.0/token
client_id=...&amp;grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&amp;device_code=...
</code></pre>

# 4 Security Considerations

1. __Secrets on the wire__: Passwords, OTPs, flow tokens, and authorization
   codes are bearer secrets. All requests MUST use TLS.
2. __Canary and cookies__: Omitting `canary` or ESTS cookies causes ESTS to
   reject or reset the flow. Clients MUST maintain a cookie jar for
   `login.microsoftonline.com`.
3. __Auth Config integrity__: `$Config` is served over TLS as part of ESTS
   HTML. Clients parse it as protocol control data, not as executable page
   script.
4. __Redirect handling__: Authorization codes appear on `Location` URIs,
   including custom schemes. Clients MUST capture `code` without navigating
   a browser document.
5. __Polling__: DeviceCodeStatus and EndAuth polling expose authentication
   state only to holders of the flow token / session cookies.
6. __Pre-MFA cookies__: `ESTSAUTH*` cookies are issued by the password
   `login` response and by ProcessAuth before an authorization code existed.
   A cookie jar holding them is not proof of a completed authentication; only
   an authorization code (or a token) is.
7. __Device flow identity__: any user can complete a device authorization
   verification page. The identity in the resulting token MUST be compared to
   the intended user.
8. __Credential handling__: the password is posted in a form field
   (`passwd`) and again as `OldPassword` / `currentpasswd` during SSPR.
   These values and OTPs MUST NOT be logged.
9. __Opaque tokens in headers__: EndAuth carries flow state in request
   headers, so intermediaries that log headers will log flow tokens.

# 5 Appendix: Endpoint Index

<table class="protocol-table"><thead>
  <tr><th><p>Endpoint</p></th><th><p>Section</p></th></tr>
</thead><tbody>
 <tr><td><p>GET odc.officeapps.live.com/odc/v2.1/federationProvider</p></td><td><p>2.1</p></td></tr>
 <tr><td><p>GET login.microsoftonline.com/{tenant}/oauth2/authorize</p></td><td><p>2.2</p></td></tr>
 <tr><td><p>Auth Config `$Config` embedded in HTML</p></td><td><p>2.3</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/GetCredentialType</p></td><td><p>2.4</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/GetOneTimeCode</p></td><td><p>2.5</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/DeviceCodeStatus</p></td><td><p>2.6</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/{tenant}/login</p></td><td><p>2.7, 2.8</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/SAS/BeginAuth</p></td><td><p>2.9</p></td></tr>
 <tr><td><p>GET/POST login.microsoftonline.com/common/SAS/EndAuth</p></td><td><p>2.10</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/common/SAS/ProcessAuth</p></td><td><p>2.11</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/{tenant}/oauth2/token</p></td><td><p>2.12</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/{tenant}/resume?skipmfaregistration=1</p></td><td><p>2.13</p></td></tr>
 <tr><td><p>POST login.microsoft.com/{tenant}/fido/get (urlFidoLogin)</p></td><td><p>2.14.1</p></td></tr>
 <tr><td><p>POST urlPost with FIDO assertion (type=23)</p></td><td><p>2.14.2</p></td></tr>
 <tr><td><p>POST urlPost with accesspass</p></td><td><p>2.15</p></td></tr>
 <tr><td><p>POST urlPost with LoginOptions=1 (KMSI / ProofUp continue)</p></td><td><p>2.16</p></td></tr>
 <tr><td><p>POST urlAsyncSsprBegin / urlAsyncSsprPoll / urlPost (password change)</p></td><td><p>2.17</p></td></tr>
 <tr><td><p>POST intermediate HTML form actions</p></td><td><p>2.18</p></td></tr>
 <tr><td><p>GET {authority}/oauth2/v2.0/authorize (silent / non-interactive code request)</p></td><td><p>2.2.2</p></td></tr>
 <tr><td><p>POST {authority}/oauth2/v2.0/token (refresh_token / password grants)</p></td><td><p>2.19.1</p></td></tr>
 <tr><td><p>POST {authority}/oauth2/v2.0/devicecode</p></td><td><p>2.19.1</p></td></tr>
 <tr><td><p>POST {authority}/oauth2/v2.0/token (device_code grant)</p></td><td><p>2.19.1</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/consumers/oauth2/v2.0/devicecode</p></td><td><p>2.19.2</p></td></tr>
 <tr><td><p>POST login.microsoftonline.com/consumers/oauth2/v2.0/token</p></td><td><p>2.19.2</p></td></tr>
</tbody></table>

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
 <tr><td><p>Password only (no MFA)</p></td><td><p>HasPassword</p></td>
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
  <td><p>External; or device-code grant alternative</p></td></tr>
 <tr><td><p>Org device code</p></td><td><p>Direct grant</p></td>
  <td><p>/oauth2/v2.0/devicecode + token poll</p></td></tr>
 <tr><td><p>Consumers device code</p></td><td><p>IfExistsResult 5 / personal account</p></td>
  <td><p>/consumers/oauth2/v2.0/devicecode + token poll</p></td></tr>
</tbody></table>
