"""Generate numbered ESTS figures; edit this file, not src/*.mmd."""

F = {}

F['fig-01-overview'] = '''flowchart TB
 A["Select tenant and authority<br/>external prerequisite"] --> B["OAuth authorize entry<br/>200 HTML with Auth Config"]
 B --> C["GetCredentialType<br/>advertise actual client capabilities"]
 C --> D{"Choose a usable offered path<br/>client capabilities and user choice"}
 D --> N["Remote NGC<br/>GetOneTimeCode, DeviceCodeStatus, login"]
 D --> F["FIDO bootstrap and assertion"]
 D --> T["Temporary Access Pass"]
 D --> P["Password login"]
 D --> I["External IdP sign-in<br/>return to ESTS /login.srf"]
 D --> X["External account flow<br/>upstream protocol"]
 P --> R{"Classify response"}
 I --> R
 N --> R
 F --> R
 T --> R
 R -->|"ConvergedTFA"| M["Choose offered MFA proof<br/>SAS, FIDO, or TAP"]
 M --> R
 R -->|"interrupt / continuation"| H["Handle advertised continuation"]
 H --> R
 R -->|"authorization response"| O(["End ESTS interaction<br/>upstream OAuth handoff, section 2.12"])
 R -->|"failure"| E(["Stop or explicit recovery"])
'''

F['fig-02-common-prefix'] = '''sequenceDiagram
 autonumber
 participant C as Client
 participant E as ESTS
 Note over C,E: Select the intended authority using upstream guidance
 C->>E: GET /{tenant}/oauth2/authorize<br/>upstream OAuth request plus applicable ESTS extensions
 E-->>C: 200 HTML with Auth Config and cookies
 Note over C,E: Parse Auth Config without executing scripts<br/>retain page state and advertised endpoint URLs
 C->>E: POST {urlGetCredentialType}<br/>username, supported capabilities, originalRequest=sCtx, flowToken=sFT
 E-->>C: JSON: Credentials, IfExistsResult, FlowToken, apiCanary
 Note over C,E: Choose a usable offered credential<br/>the listed paths do not impose an attempt order
'''

F['fig-03-path-selection'] = '''flowchart TB
 S["GetCredentialType"] --> A{"Account routing"}
 A -->|"no account / throttled / error"| E(["Handle discovery outcome"])
 A -->|"personal account route"| X(["External sign-in<br/>upstream references, section 2.19"])
 A -->|"organizational route"| C{"Select offered credential<br/>with user choice and actual client support"}
 C -->|"HasAccessPass"| T["TAP, Figure 6"]
 C -->|"RemoteNgcParams"| N["Remote NGC, Figure 4"]
 C -->|"FidoParams and usable authenticator"| F["FIDO, Figure 7"]
 C -->|"FederationRedirectUrl"| I["IdP sign-in and ESTS return, Figure 18"]
 C -->|"HasPassword"| P["Password login, Figure 5"]
 C -->|"no usable path"| U(["External interaction required"])
 C -.- H["PrefCredential is a hint<br/>not a fixed attempt order"]
'''

F['fig-04-remote-ngc'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant A as Authenticator app<br/>(user device)
  Note over C,E: Common prefix: authorize and GetCredentialType (Figure 2)<br/>Credentials.RemoteNgcParams{SessionIdentifier, Entropy, Application}
  C->>E: POST /common/GetOneTimeCode (JSON)<br/>headers: canary, client-request-id<br/>body: Channel=Authenticator, FlowToken=sFT, OriginalRequest=sCtx,<br/>OldDeviceCode=RemoteNgcParams.SessionIdentifier
  E-->>C: 200 JSON: RemoteNgcParams{SessionIdentifier, Entropy, DefaultType: 3, UserCode}
  E-)A: push notification (out of band)
  Note over C,E: Use returned SessionIdentifier and Entropy; display number match
  loop pending within a finite local deadline; stop on cancellation or failure
    C->>E: POST {urlSessionState}?code={SessionIdentifier}<br/>header canary, body {DeviceCode}
    E-->>C: 200 {AuthorizationState: 0}  (pending)
  end
  A->>E: user approves number match
  C->>E: POST {urlSessionState}?code={SessionIdentifier}
  E-->>C: 200 {AuthorizationState: 2}  (approved)
  C->>E: POST /{tenant}/login (form)<br/>code, psRNGCSLK, login, loginfmt, psRNGCEntropy,<br/>flowToken, canary, ctx
  alt authorization code issued
    E-->>C: 302 Location: {redirect_uri}?code=...&session_state=...<br/>+ ESTSAUTH, ESTSAUTHPERSISTENT, CCState, ...
    Note over C,E: ESTS complete: upstream OAuth handoff (section 2.12)
  else interrupt
    E-->>C: 200 HTML with $Config (KMSI, ProofUp, ...) (Figure 13)
  end
'''

F['fig-05-password-branch'] = '''flowchart LR
  A["POST /{tenant}/login<br/>login, passwd, ctx, flowToken, canary,<br/>client_id, client-request-id"] --> B{"Response"}
  B -->|"302 with code"| T(["Authorization response (Figure 23)<br/>no additional MFA challenge"])
  B -->|"200 pgid=ConvergedTFA<br/>arrUserProofs, urlBeginAuth, urlEndAuth, urlPost"| M{"Select an arrUserProofs entry"}
  B -->|"200 pgid=KmsiInterrupt"| K["KMSI continue (Figure 14)"]
  B -->|"200 pgid=ConvergedProofUpRedirect"| PU["MFA registration interrupt (Figure 15)"]
  B -->|"200 pgid=ConvergedChangePassword"| SS["Password change (Figure 16)"]
  B -->|"200 pgid=ConvergedConsent"| CO(["terminal: consent required"])
  B -->|"200 auto-submit HTML"| AS["Auto-submit loop (Figure 17)"]
  B -->|"200 Auth Config with sErrorCode<br/>50126, 50053, ..."| ER(["credential failure (Figure 22)"])
  M -->|"PhoneAppNotification, CompanionAppsNotification"| S1["SAS poll (Figure 8)"]
  M -->|"PhoneAppOTP"| S2["SAS OTP (Figure 9)"]
  M -->|"OneWaySMS, ConsolidatedTelephony"| S3["SAS SMS (Figure 10)"]
  M -->|"TwoWayVoiceMobile, TwoWayVoiceAlternateMobile, TwoWayVoiceOffice"| S4["SAS voice (Figure 11)"]
  M -->|"FidoKey"| S5["FIDO (Figure 12)"]
  M -->|"AccessPass"| S6["TAP (Figure 6)"]
'''

F['fig-06-tap'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User
  alt passwordless (GetCredentialType)
    Note over C,E: Credentials.HasAccessPass is true<br/>(request flag isAccessPassSupported=true)
  else after password login
    Note over C,E: ConvergedTFA arrUserProofs contains AccessPass
  end
  Note over C,E: BeginAuth is not used for AccessPass
  U-->>C: Temporary Access Pass
  C->>E: POST {urlPost} (form)<br/>login, loginfmt, accesspass, canary, hpgrequestid=sessionId, flowToken,<br/>ctx (or request when urlPost contains ProcessAuth)
  alt authorization code issued
    E-->>C: 302 Location with code
  else interrupt or auto-submit
    E-->>C: 200 HTML ($Config or auto-submit form)
  end
'''

F['fig-07-fido-passwordless'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant K as FIDO authenticator<br/>(local, outside ESTS HTTP)
  participant E as ESTS<br/>login.microsoftonline.com
  participant EF as login.microsoft.com
  Note over C,E: GetCredentialType returned Credentials.FidoParams{AllowList, ...}<br/>(request flag isFidoSupported=true)
  C->>EF: POST {urlFidoLogin} (/{tenant}/fido/get?uiflavor=Host)<br/>browser User-Agent, flow=mfa, allowedIdentities, canary, serverChallenge, postBackUrl, postBackUrlAad,<br/>cancelUrl, resumeUrl, correlationId, credentialsJson=AllowList[0] unchanged, ctx, username, loginCanary
  EF-->>C: 200 HTML with a new $Config<br/>sFidoChallenge, sCrossDomainCanary, sessionId
  Note over C,E: Keep initiating page urlPost, sFT, sCtx, canary<br/>Take challenge, cross-domain canary, and sessionId from bootstrap
  C->>K: challenge from sFidoChallenge
  K-->>C: WebAuthn assertion
  C->>E: POST {initiating-page urlPost} (form)<br/>type=23, ps=23, assertion, lmcCanary=sCrossDomainCanary,<br/>hpgrequestid=sessionId, ctx, canary, flowToken
  alt code delivered
    E-->>C: 302 Location with code<br/>or 200 HTML whose anchor href carries code
  else another proof, interrupt, or auto-submit
    E-->>C: 200 HTML (Figure 13, Figure 17)
  end
'''

F['fig-08-sas-notification'] = '''sequenceDiagram
 autonumber
 participant C as Client
 participant E as ESTS
 participant A as User notification app
 Note over C,E: ConvergedTFA offers PhoneAppNotification or CompanionAppsNotification
 C->>E: POST {urlBeginAuth} (JSON), header canary<br/>AuthMethodId=selected method, Method=BeginAuth, ctx=sCtx, flowToken=sFT
 E-->>C: Success=true, FlowToken, Ctx, SessionId, Entropy
 E-)A: challenge notification
 Note over C,E: Display Entropy when applicable; retain MFA page state separately<br/>SAS canary header forms: page canary or apiCanary (section 2.9)
 loop pending within attempt and deadline bounds
  C->>E: GET {urlEndAuth}?authMethodId={selected}&pollCount={n}<br/>x-ms-sessionId, x-ms-flowToken, x-ms-ctx
  E-->>C: Success=false, Retry=true, pending state
  Note over C,E: Retained-state pattern: page sessionId plus BeginAuth token/context<br/>Response-state pattern: preceding SAS SessionId/token/context
 end
 A->>E: user approves
 C->>E: GET {urlEndAuth} (next poll)
 E-->>C: Success=true, FlowToken, Ctx
 C->>E: POST {MFA-page urlPost} (form)<br/>request=successful Ctx, flowToken=successful FlowToken,<br/>mfaAuthMethod=selected, login, canary=MFA-page canary
 E-->>C: Authorization response, interrupt, continuation, or error
 Note over C,E: Dispatch response; OAuth handoff only after authorization response
'''

F['fig-09-sas-otp'] = '''sequenceDiagram
 autonumber
 participant C as Client
 participant E as ESTS
 participant U as User
 Note over C,E: ConvergedTFA offers PhoneAppOTP
 C->>E: POST {urlBeginAuth}<br/>AuthMethodId=PhoneAppOTP, Method=BeginAuth, ctx, flowToken; SAS canary header
 E-->>C: Success=true, FlowToken, Ctx, SessionId
 loop user submits a code within local deadline
  U-->>C: OTP as a string, preserving leading zeroes
  C->>E: POST {urlEndAuth} (JSON)<br/>AdditionalAuthData=trimmed OTP, AuthMethodId, Method=EndAuth,<br/>BeginAuth SessionId, FlowToken, Ctx; SAS canary header
  alt recoverable code rejection
   E-->>C: Success=false, diagnostic code-rejection details<br/>Retry may be absent or false
   Note over C,E: Re-prompt using retained challenge state; do not repeat BeginAuth<br/>Do not infer recoverability merely from presence of Message
  else terminal or unrecognized failure
   E-->>C: Failure or HTML service error
   break terminal failure
    Note over C,E: Stop or explicit recovery; no ProcessAuth
   end
  else code accepted
   E-->>C: Success=true, FlowToken, Ctx
   C->>E: POST {MFA-page urlPost}<br/>request=successful Ctx, flowToken=successful FlowToken,<br/>mfaAuthMethod=PhoneAppOTP, login, MFA-page canary
   E-->>C: Authorization response, interrupt, continuation, or error
   break code accepted
    Note over C,E: Leave code-entry loop and dispatch completion response
   end
  end
 end
'''

F['fig-10-sas-sms'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User phone
  Note over C,E: arrUserProofs contains OneWaySMS or ConsolidatedTelephony<br/>(display carries a masked phone number)
  C->>E: POST /common/SAS/BeginAuth  header canary (SAS form, section 2.9)<br/>{AuthMethodId: OneWaySMS | ConsolidatedTelephony, Method: BeginAuth, ctx, flowToken}
  E-->>C: 200 {Success: true, FlowToken, Ctx, SessionId}
  E-)U: SMS code (out of band)
  U-->>C: SMS code
  C->>E: POST /common/SAS/EndAuth (JSON)  header canary (SAS form, section 2.9)<br/>{AdditionalAuthData: smsCode, AuthMethodId, SessionId, FlowToken, Ctx, Method: EndAuth}
  E-->>C: 200 {Success: true, FlowToken, Ctx}
  Note over C,E: Code rejection: apply code-entry retry rules (Figure 9)
  C->>E: POST /common/SAS/ProcessAuth (form)<br/>mfaAuthMethod=OneWaySMS  (even when the method was ConsolidatedTelephony)
  E-->>C: 302 code, or 200 interrupt HTML
'''

F['fig-11-sas-voice'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User phone
  Note over C,E: arrUserProofs contains TwoWayVoiceMobile, TwoWayVoiceAlternateMobile or TwoWayVoiceOffice
  C->>E: POST /common/SAS/BeginAuth  header canary (SAS form, section 2.9)<br/>{AuthMethodId: TwoWayVoice..., Method: BeginAuth, ctx, flowToken}
  E-->>C: 200 {Success: true, FlowToken, Ctx, SessionId}
  E-)U: automated call (out of band)
  loop while Success is false and Retry is true, up to the attempt limit
    C->>E: GET /common/SAS/EndAuth?authMethodId=TwoWayVoice...&pollCount={n}<br/>x-ms-sessionId, x-ms-flowToken, x-ms-ctx (one pattern from Figure 8)
    E-->>C: 200 {Success: false, ResultValue: AuthenticationPending, Retry: true}
  end
  U->>E: answers and confirms the call
  C->>E: GET /common/SAS/EndAuth?...
  E-->>C: 200 {Success: true, FlowToken, Ctx}
  C->>E: POST /common/SAS/ProcessAuth (form)<br/>request, mfaAuthMethod (same value), login, flowToken, canary
  E-->>C: 302 code, or 200 interrupt HTML
'''

F['fig-12-fido-from-tfa'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant K as FIDO authenticator<br/>(local)
  participant E as ESTS
  participant EF as login.microsoft.com
  C->>E: POST /{tenant}/login  (username and password, Figure 5)
  E-->>C: 200 pgid=ConvergedTFA<br/>arrUserProofs includes FidoKey<br/>Auth Config also contains arrFidoAllowList, urlFidoLogin, iAllowedIdentities, urlPost
  Note over C,E: BeginAuth is not used for FidoKey
  C->>EF: POST {urlFidoLogin}<br/>credentialsJson=arrFidoAllowList[0] unchanged, other fields as in Figure 7
  EF-->>C: 200 HTML with a new $Config<br/>sFidoChallenge, sCrossDomainCanary, sessionId
  Note over C,E: Keep initiating page urlPost, sFT, sCtx, canary<br/>Take challenge, cross-domain canary, and sessionId from bootstrap
  C->>K: challenge
  K-->>C: assertion
  C->>E: POST {initiating-page urlPost}: type=23, ps=23, assertion, lmcCanary, hpgrequestid, ctx, canary, flowToken
  E-->>C: Authorization response, ConvergedTFA, interrupt, or continuation
'''

F['fig-13-interrupts'] = '''flowchart TB
 A["Response after primary authentication or proof completion"] --> B{"Classify response"}
 B -->|"authorization response"| T(["ESTS complete<br/>upstream OAuth handoff"])
 B -->|"continuation form"| AS["Submit genuine continuation<br/>bounded hops / deadline, Figure 17"]
 B -->|"HTML with Auth Config"| P{"Page state and errors"}
 P -->|"ConvergedTFA"| M["Select another offered usable proof"]
 P -->|"KmsiInterrupt"| K["POST advertised continuation, Figure 14"]
 P -->|"ProofUp with skip URL"| S["Skip resume, Figure 15"]
 P -->|"ProofUp with offered postponement"| D["Postponement continuation, Figure 15"]
 P -->|"ProofUp without continuation / consent"| I(["External interaction required"])
 P -->|"ConvergedChangePassword"| SS["SSPR, Figure 16"]
 P -->|"credential or service failure"| E(["Stop or explicit recovery, Figure 22"])
 AS --> B
 M --> B
 K --> B
 S --> B
 D --> B
 SS --> B
'''

F['fig-14-kmsi'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  Note over C,E: Prior response: 200 HTML, pgid = KmsiInterrupt
  C->>E: POST {urlPost} (form)<br/>LoginOptions=1, ctx, flowToken=sFT (interrupt page), canary, client-request-id
  alt authorization code issued
    E-->>C: 302 Location with code and session_state
  else further interrupt
    E-->>C: 200 HTML with a new $Config (re-parse)
  end
'''

F['fig-15-proofup'] = '''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS<br/>login.microsoftonline.com
  participant R as mysignins.microsoft.com<br/>(registration, not specified)
  Note over C,E: After ProcessAuth or login: 200 pgid=ConvergedProofUpRedirect<br/>sErrorCode can be 50203; skip URL may exist without remaining-days metadata<br/>urlPost on the registration host, no sCtx
  alt registration required or chosen
    C-xR: register a method (out of scope)
  else skip (urlSkipMfaRegistration advertised)
    C->>E: POST /{tenant}/resume?skipmfaregistration=1 (form)<br/>flowtoken=sFT, ctx=request value posted to ProcessAuth, canary
    E-->>C: 302 Location with code and session_state<br/>+ authenticated cookies, CCState, SignInStateCookie
  else postponement is offered (remaining days)
    C->>E: POST current urlPost: LoginOptions=1, ctx, flowToken (preceding page), canary (interrupt page)
    E-->>C: new $Config, 302 with code, or further interrupt
  end
'''

F['fig-16-sspr'] = '''sequenceDiagram
 autonumber
 participant C as Client
 participant E as ESTS
 Note over C,E: ConvergedChangePassword advertises begin, poll, and confirmation URLs
 C->>E: POST {urlAsyncSsprBegin} (JSON)<br/>Ctx=sCtx, FlowToken=sFT, OldPassword, NewPassword
 E-->>C: IsJobPending, Ctx, FlowToken, routing fields, ErrorMessage
 loop job pending within local deadline
  C->>E: POST {urlAsyncSsprPoll} (JSON)<br/>preceding Ctx, FlowToken, CoupledDataCenter, CoupledScaleUnit
  E-->>C: Updated job state and ErrorMessage
 end
 Note over C,E: Confirm only when completed without ErrorMessage
 alt JSON confirmation
  C->>E: POST {urlPost} (JSON)<br/>Ctx, FlowToken, currentpasswd, confirmnewpasswd, canary
 else form confirmation
  C->>E: POST {urlPost} (form)<br/>ctx, flowToken, currentpasswd, confirmnewpasswd, canary
 end
 E-->>C: Confirmation status, authorization response, or page
 Note over C,E: Dispatch returned page; restart with new password only if continuation unavailable<br/>Restart is client recovery, not a required server transition
'''

F['fig-17-autosubmit'] = '''flowchart TB
  A["200 HTML response"] --> B{"Interstitial<br/>marker present?"}
  B -.- MK["Markers (substring match on body):<br/>Click Submit to continue<br/>Working...<br/>Click here to finish the authorization process<br/>input type=submit"]
  B -->|no| C{"Authorization response?<br/>(Figure 23)"}
  C -->|yes| T(["extract code"])
  C -->|no| P["Parse $Config<br/>(Figure 13 / Figure 22)"]
  B -->|yes| D["Parse first form<br/>resolve action against response URL"]
  D --> E["Collect enabled continuation inputs<br/>with name and value; preserve duplicates"]
  E --> F["POST to action<br/>(application/x-www-form-urlencoded)"]
  F -->|"next response within hop / deadline bounds"| B
  F -->|"cancel / limit / repeated loop"| X(["Stop; no automatic restart"])
'''

F['fig-18-consumers-federated'] = '''flowchart TB
 G["Credential discovery"] --> Q{"Account / credential route"}
 Q -->|"personal-account route"| C(["External account interaction<br/>upstream references, section 2.19"])
 Q -->|"FederationRedirectUrl"| I["External IdP sign-in<br/>IdP protocol outside ESTS"]
 I --> R["Federation return<br/>POST returned sign-in form to authority-origin /login.srf"]
 R --> O{"ESTS response"}
 O -->|"authorization response"| A(["Upstream OAuth handoff"])
 O -->|"ConvergedTFA"| M["Choose usable offered proof<br/>same SAS, FIDO, or TAP paths"]
 O -->|"interrupt / continuation"| P["Response dispatcher, Figure 13"]
 M --> P
 O -->|"failure"| E(["Stop or explicit recovery"])
'''

F['fig-19-v1-v2'] = '''flowchart TB
 O["Upstream OAuth authorization request"] --> E["ESTS entry<br/>HTML Auth Config and credential discovery"]
 E --> M["Primary authentication and MFA<br/>endpoint-specific state and proofs"]
 M --> I{"ESTS response"}
 I -->|"another proof / continuation"| M
 I -->|"authorization response"| H(["End ESTS interaction<br/>upstream OAuth handoff, section 2.12"])
 I -->|"error / external interaction"| X(["Stop or explicit recovery"])
'''

F['fig-20-token-lineage'] = '''sequenceDiagram
 participant C as Client state
 participant E as ESTS
 Note over C,E: Entry page: retain sFT, sCtx, canary, sessionId, and URLs<br/>Discovery and Remote NGC do not blanket-replace entry state
 C->>E: BeginAuth using MFA-page sFT, sCtx, and SAS canary
 E-->>C: Save SAS SessionId, FlowToken, and Ctx separately
 alt EndAuth GET, retained-state pattern
  C->>E: x-ms-sessionId = MFA-page sessionId<br/>x-ms-flowToken and x-ms-ctx = BeginAuth values
  E-->>C: Pending, keep BeginAuth token and context for next poll
 else EndAuth GET, response-state pattern
  C->>E: x-ms-sessionId, x-ms-flowToken, x-ms-ctx<br/>from preceding SAS response
  E-->>C: Pending, save returned SAS state for next poll
 else EndAuth POST, code entry
  C->>E: BeginAuth SessionId, FlowToken, Ctx, plus entered code
  E-->>C: Recoverable code rejection can permit another entry<br/>keep challenge state, do not repeat BeginAuth
 end
 E-->>C: Successful EndAuth supplies completion FlowToken and Ctx
 C->>E: ProcessAuth: flowToken = successful FlowToken<br/>request = successful Ctx, canary = MFA-page canary
 opt ProofUp skip URL advertised
  E-->>C: New ProofUp sFT and canary, sCtx can be absent
  C->>E: Skip resume: flowtoken = ProofUp sFT, canary = ProofUp canary<br/>ctx = preceding ProcessAuth request when sCtx is absent
 end
 Note over C,E: FIDO uses a separate bootstrap without blanket state replacement<br/>Keep initiating urlPost, sFT, sCtx, and canary<br/>Bootstrap supplies challenge, cross-domain canary, and completion sessionId
'''

F['fig-21-cookies'] = '''sequenceDiagram
 autonumber
 participant C as Client cookie jar
 participant E as ESTS
 C->>E: Authorize and discovery
 E-->>C: Page / context / routing cookies as issued
 C->>E: Primary authentication
 E-->>C: ESTSAUTH cookies may already be present before MFA
 Note over C,E: Cookie presence does not prove MFA or authorization completion
 C->>E: SAS BeginAuth / EndAuth
 E-->>C: Challenge state and any Set-Cookie updates
 C->>E: ProcessAuth / advertised continuation
 E-->>C: Cookie rotations and authorization response or interrupt
 Note over C,E: Honor cookie domain, path, expiry, and deletion<br/>No fixed cookie inventory or rotation sequence is required
'''

F['fig-22-errors'] = '''flowchart TB
 R["ESTS response"] --> C{"Response channel"}
 C -->|"HTML"| H["Auth Config pgid and error fields<br/>numeric or symbolic sErrorCode"]
 C -->|"SAS JSON"| S{"Success?"}
 C -->|"Remote NGC JSON"| N["AuthorizationState: pending / denied / approved<br/>unknown state requires explicit failure handling"]
 C -->|"authorization response"| O["Upstream OAuth error handling"]
 H --> P{"Actionable interrupt or error?"}
 P -->|"initial 50058 / advertised ProofUp skip"| A["Continue according to page state"]
 P -->|"credential / service error"| E(["Stop or explicit recovery"])
 S -->|"true"| F["Complete with successful state"]
 S -->|"false: polling"| Q{"Retry"}
 Q -->|"true within bounds"| W["Wait and poll"]
 Q -->|"false / unrecognized"| E
 S -->|"false: code submission"| K{"Recoverable code rejection?"}
 K -->|"yes, even if Retry absent or false"| T["Re-prompt using retained challenge state"]
 K -->|"terminal / unrecognized"| E
'''

F['fig-23-authz-response'] = '''flowchart TB
  A["Response to a POST that can complete the flow<br/>(or a silent authorize request)"] --> B{"Delivery form"}
  B -->|"302 with Location"| L["Parse Location URL<br/>read code, session_state<br/>error present means failure; description is optional"]
  B -->|"302 with HTML body containing an anchor"| H["Read anchor href with an HTML parser<br/>parse URL, then decode query values once"]
  B -->|"200 HTML with document.location.replace(url)"| J["Decode JavaScript string escapes<br/>parse URL, read code or error"]
  B -->|"200 HTML from FIDO assertion post<br/>with anchor"| FA["Parse anchor href<br/>for code or error"]
  B -->|"none of the above"| P["Check auto-submit form (Figure 17),<br/>then Auth Config (interrupt or error)"]
  L --> X
  H --> X
  J --> X
  FA --> X
  X["Apply upstream response validation<br/>section 2.12"] -->|"authorization response accepted"| HANDOFF(["ESTS complete: upstream OAuth handoff"])
  X -->|"error or invalid binding"| REJECT(["Stop"])
'''

import re,textwrap
def wrap_text(t,w=54):
    parts=t.split('<br/>')
    out=[]
    for p in parts:
        out+=textwrap.wrap(p,w,break_long_words=False,break_on_hyphens=False) or ['']
    return '<br/>'.join(out)
def fix_seq(src):
    lines=src.split('\n'); out=[]; parts=[]
    for ln in lines:
        m=re.match(r'\s*participant (\w+)',ln)
        if m: parts.append(m.group(1))
        m=re.match(r'(\s*)(loop|opt)\s+(.*)',ln)
        if m and len(m.group(3))>34:
            out.append('%s%s repeat'%(m.group(1),m.group(2)) if m.group(2)=='loop' else '%sopt details'%m.group(1))
            out.append('%s  Note over %s,%s: %s'%(m.group(1),parts[0],parts[1],wrap_text(m.group(3),70)))
            continue
        m=re.match(r'(\s*)(Note over [^:]+:)\s*(.*)',ln)
        if m: out.append(m.group(1)+m.group(2)+' '+wrap_text(m.group(3),70)); continue
        m=re.match(r'(\s*)((\w+)\s*(?:-->>|->>|-\)|-x|--\))\s*(\w+):)\s*(.*)',ln)
        if m:
            ind,pre,a,b,txt=m.group(1),m.group(2),m.group(3),m.group(4),m.group(5)
            pieces=txt.split('<br/>')
            head=pieces[0]; det=pieces[1:]
            hw=textwrap.wrap(head,64,break_long_words=False,break_on_hyphens=False)
            head='<br/>'.join(hw[:2]); det=hw[2:]+det
            out.append(ind+pre+' '+head)
            if det:
                out.append('%sNote over %s,%s: %s'%(ind,a,b,wrap_text('<br/>'.join(det),72)))
            continue
        out.append(ln)
    return '\n'.join(out)
for k in list(F):
    if F[k].startswith('sequenceDiagram'): F[k]=fix_seq(F[k].replace(';', ','))
from pathlib import Path
source_dir = Path(__file__).resolve().parent / 'src'
source_dir.mkdir(parents=True, exist_ok=True)
for k,v in F.items():
    (source_dir / ('%s.mmd' % k)).write_text(v, encoding='utf-8')
print(len(F))
