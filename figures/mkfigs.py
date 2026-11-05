F={}
F['fig-01-overview']='''flowchart TB
  A["1. Federation provider discovery<br/>GET odc.officeapps.live.com/odc/v2.1/federationProvider<br/>(optional)"] --> B
  B["2. Authorize<br/>GET /{tenant}/oauth2/authorize<br/>200 HTML with $Config (sFT, sCtx, canary)"] --> C
  C["3. GetCredentialType<br/>POST /common/GetCredentialType<br/>capability flags and credential parameter blocks"] --> D{"Path selection<br/>(Figure 2)"}
  D -->|"RemoteNgcParams"| P1["Passwordless Remote NGC<br/>GetOneTimeCode, DeviceCodeStatus poll, login"]
  D -->|"FidoParams"| P2["Passwordless FIDO<br/>urlFidoLogin, assertion post"]
  D -->|"HasAccessPass"| P3["Passwordless TAP<br/>post accesspass"]
  D -->|"HasPassword"| P4["Password<br/>POST /{tenant}/login"]
  D -->|"FederationRedirectUrl"| P5["Federated IdP<br/>(browser redirect, out of scope)"]
  D -->|"IfExistsResult 5"| P6["Consumers device code grant"]
  P4 --> E{"Login outcome<br/>(Figure 5)"}
  E -->|"ConvergedTFA"| M["SAS MFA<br/>BeginAuth, EndAuth, ProcessAuth<br/>or FIDO / TAP"]
  E -->|"interrupt page"| I["Post-authentication interrupts<br/>(Figure 13)"]
  E -->|"302 with code"| T
  P1 --> I
  P2 --> I
  P3 --> I
  M --> I
  I --> T["Authorization response<br/>(Figure 20)<br/>extract code"]
  P1 -->|"302 with code"| T
  T --> TK["Token exchange<br/>POST /{tenant}/oauth2/token<br/>grant_type=authorization_code"]
  TK --> OUT(["access_token, refresh_token, id_token"])
'''
F['fig-02-path-selection']='''flowchart TB
  S["GetCredentialType response"] --> Q0{"IfExistsResult"}
  Q0 -->|"1 (no account)"| X1(["abort sign-in"])
  Q0 -->|"2 (throttled) or 4 (server error)"| X2(["wait and retry"])
  Q0 -->|"5 (personal account)"| DC["Consumers device code grant<br/>(Figure 19)"]
  Q0 -->|"0 or 6"| Q1{"Credentials.HasAccessPass<br/>true?"}
  Q1 -->|yes| TAP["Passwordless TAP<br/>(Figure 12)"]
  Q1 -->|no| Q2{"RemoteNgcParams<br/>non-null?"}
  Q2 -->|yes| NGC["Passwordless Remote NGC<br/>(Figure 4)"]
  Q2 -->|no| Q3{"FidoParams<br/>non-null?"}
  Q3 -->|yes| FIDO["Passwordless FIDO<br/>(Figure 10)"]
  Q3 -->|no| Q4{"FederationRedirectUrl<br/>present?"}
  Q4 -->|yes| FED["Federated IdP<br/>(Figure 19)"]
  Q4 -->|no| Q5{"HasPassword<br/>true?"}
  Q5 -->|yes| PW["Password submission<br/>(Figure 5)"]
  Q5 -->|no| X3(["no supported path"])
'''
F['fig-03-common-prefix']='''sequenceDiagram
  autonumber
  participant C as Client
  participant O as odc.officeapps.live.com
  participant E as ESTS<br/>login.microsoftonline.com
  opt federation discovery
    C->>O: GET /odc/v2.1/federationProvider?domain={domain}
    O-->>C: 200 JSON: tenantId, authority_host, endpoint[OrgId, MSA]
  end
  C->>E: GET /{tenant}/oauth2/authorize<br/>client_id, response_type=code, redirect_uri, client-request-id, resource, optional OpenID Connect scope, ...
  E-->>C: 200 text/html + Set-Cookie (buid, esctx, esctx-{id}, fpc, ...)
  Note over C,E: Extract the $Config object from the script element.<br/>Keep sFT, sCtx, canary, apiCanary, sessionId, pgid,<br/>url* values. sErrorCode 50058 on this page is not an error.
  C->>E: POST /common/GetCredentialType?mkt=en-US (JSON)<br/>username, capability flags, originalRequest=sCtx, flowToken=sFT
  E-->>C: 200 JSON (GetCredentialType response)<br/>IfExistsResult, Credentials{HasPassword, RemoteNgcParams, FidoParams, HasAccessPass, FederationRedirectUrl}, FlowToken, apiCanary
  Note over C,E: Select path from populated parameter blocks (Figure 2)
'''
F['fig-04-remote-ngc']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant A as Authenticator app<br/>(user device)
  Note over C,E: Common prefix: authorize and GetCredentialType (Figure 3)<br/>Credentials.RemoteNgcParams{SessionIdentifier, Entropy, Application}
  C->>E: POST /common/GetOneTimeCode (JSON)<br/>headers: canary, client-request-id<br/>body: Channel=Authenticator, FlowToken=sFT, OriginalRequest=sCtx,<br/>OldDeviceCode=RemoteNgcParams.SessionIdentifier
  E-->>C: 200 JSON: RemoteNgcParams{SessionIdentifier, Entropy, DefaultType: 3, UserCode}
  E-)A: push notification (out of band)
  Note over C,E: Display Entropy (number match) to the user
  loop while AuthorizationState is 0 (about every 5 seconds, stop on timeout)
    C->>E: POST {urlSessionState}?code={SessionIdentifier}<br/>header canary, body {DeviceCode}
    E-->>C: 200 {AuthorizationState: 0}  (pending)
  end
  A->>E: user approves number match
  C->>E: POST {urlSessionState}?code={SessionIdentifier}
  E-->>C: 200 {AuthorizationState: 2}  (approved)
  C->>E: POST /{tenant}/login (form)<br/>code, psRNGCSLK, login, loginfmt, psRNGCEntropy,<br/>flowToken, canary, ctx
  alt authorization code issued
    E-->>C: 302 Location: {redirect_uri}?code=...&session_state=...<br/>+ ESTSAUTH, ESTSAUTHPERSISTENT, CCState, ...
    C->>E: POST /{tenant}/oauth2/token (code exchange, Figure 20)
  else interrupt
    E-->>C: 200 HTML with $Config (KMSI, ProofUp, ...) (Figure 13)
  end
'''
F['fig-05-password-branch']='''flowchart LR
  A["POST /{tenant}/login<br/>login, passwd, ctx, flowToken, canary,<br/>client_id, client-request-id"] --> B{"Response"}
  B -->|"302 with code"| T(["Authorization response (Figure 20)<br/>no additional MFA challenge"])
  B -->|"200 pgid=ConvergedTFA<br/>arrUserProofs, urlBeginAuth, urlEndAuth, urlPost"| M{"Select an arrUserProofs entry"}
  B -->|"200 pgid=KmsiInterrupt"| K["KMSI continue (Figure 14)"]
  B -->|"200 pgid=ConvergedProofUpRedirect"| PU["MFA registration interrupt (Figure 15)"]
  B -->|"200 pgid=ConvergedChangePassword"| SS["Password change (Figure 16)"]
  B -->|"200 pgid=ConvergedConsent"| CO(["terminal: consent required"])
  B -->|"200 auto-submit HTML"| AS["Auto-submit loop (Figure 17)"]
  B -->|"200 Auth Config with sErrorCode<br/>50126, 50053, ..."| ER(["credential failure (Figure 22)"])
  M -->|"PhoneAppNotification, CompanionAppsNotification"| S1["SAS poll (Figure 6)"]
  M -->|"PhoneAppOTP"| S2["SAS OTP (Figure 7)"]
  M -->|"OneWaySMS, ConsolidatedTelephony"| S3["SAS SMS (Figure 8)"]
  M -->|"TwoWayVoiceMobile, TwoWayVoiceAlternateMobile, TwoWayVoiceOffice"| S4["SAS voice (Figure 9)"]
  M -->|"FidoKey"| S5["FIDO (Figure 11)"]
  M -->|"AccessPass"| S6["TAP (Figure 12)"]
'''
F['fig-06-sas-notification']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant A as Authenticator app
  Note over C,E: Password login returned pgid=ConvergedTFA (Figure 5)
  C->>E: POST /common/SAS/BeginAuth (JSON)  header canary<br/>{AuthMethodId: PhoneAppNotification, Method: BeginAuth, ctx: sCtx, flowToken: sFT}
  E-->>C: 200 {Success: true, Entropy, FlowToken, Ctx, SessionId, ...}
  E-)A: push notification (out of band)
  Note over C,E: Replace working flowToken and ctx with the BeginAuth FlowToken and Ctx.<br/>Display Entropy for number matching.
  loop pollCount = 1, 2, ... up to iMaxPollAttempts, interval iPollingInterval (about 5 s)
    C->>E: GET /common/SAS/EndAuth?authMethodId=PhoneAppNotification&pollCount={n}<br/>headers x-ms-sessionId ($Config.sessionId), x-ms-flowToken, x-ms-ctx
    E-->>C: 200 {Success: false, ResultValue: AuthenticationPending, Retry: true}
  end
  A->>E: user approves
  C->>E: GET /common/SAS/EndAuth?...
  E-->>C: 200 {Success: true, FlowToken, Ctx, MobileAppAuthDetails}
  C->>E: POST /common/SAS/ProcessAuth (form)<br/>request=Ctx, mfaAuthMethod, login, flowToken, canary
  alt authorization code issued
    E-->>C: 302 Location: {redirect_uri}?code=...
  else interrupt
    E-->>C: 200 HTML (ConvergedProofUpRedirect, KMSI, ...) (Figure 13)
  end
  C->>E: POST /{tenant}/oauth2/token
  E-->>C: 200 access_token, refresh_token, id_token
'''
F['fig-07-sas-otp']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User / Authenticator app
  Note over C,E: ConvergedTFA arrUserProofs contains PhoneAppOTP
  C->>E: POST /common/SAS/BeginAuth  header canary<br/>{AuthMethodId: PhoneAppOTP, Method: BeginAuth, ctx, flowToken}
  E-->>C: 200 {Success: true, FlowToken, Ctx, SessionId}
  U-->>C: TOTP code (out of band, from the app)
  C->>E: POST /common/SAS/EndAuth (JSON)  header canary<br/>{AdditionalAuthData: otp, AuthMethodId, SessionId, FlowToken, Ctx, Method: EndAuth}
  alt code accepted
    E-->>C: 200 {Success: true, FlowToken, Ctx}
    C->>E: POST /common/SAS/ProcessAuth (form)<br/>request, mfaAuthMethod=PhoneAppOTP, login, flowToken, canary
    E-->>C: 302 code, or 200 interrupt HTML
  else code rejected
    E-->>C: 200 {Success: false, Retry: false, ErrCode}
  end
'''
F['fig-08-sas-sms']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User phone
  Note over C,E: arrUserProofs contains OneWaySMS or ConsolidatedTelephony<br/>(display carries a masked phone number)
  C->>E: POST /common/SAS/BeginAuth  header canary<br/>{AuthMethodId: OneWaySMS | ConsolidatedTelephony, Method: BeginAuth, ctx, flowToken}
  E-->>C: 200 {Success: true, FlowToken, Ctx, SessionId}
  E-)U: SMS code (out of band)
  U-->>C: SMS code
  C->>E: POST /common/SAS/EndAuth (JSON)  header canary<br/>{AdditionalAuthData: smsCode, AuthMethodId, SessionId, FlowToken, Ctx, Method: EndAuth}
  E-->>C: 200 {Success: true, FlowToken, Ctx}
  C->>E: POST /common/SAS/ProcessAuth (form)<br/>mfaAuthMethod=OneWaySMS  (even when the method was ConsolidatedTelephony)
  E-->>C: 302 code, or 200 interrupt HTML
'''
F['fig-09-sas-voice']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  participant U as User phone
  Note over C,E: arrUserProofs contains TwoWayVoiceMobile, TwoWayVoiceAlternateMobile or TwoWayVoiceOffice
  C->>E: POST /common/SAS/BeginAuth  header canary<br/>{AuthMethodId: TwoWayVoice..., Method: BeginAuth, ctx, flowToken}
  E-->>C: 200 {Success: true, FlowToken, Ctx, SessionId}
  E-)U: automated call (out of band)
  loop while Success is false and Retry is true, up to the attempt limit
    C->>E: GET /common/SAS/EndAuth?authMethodId=TwoWayVoice...&pollCount={n}<br/>x-ms-sessionId, x-ms-flowToken, x-ms-ctx
    E-->>C: 200 {Success: false, ResultValue: AuthenticationPending, Retry: true}
  end
  U->>E: answers and confirms the call
  C->>E: GET /common/SAS/EndAuth?...
  E-->>C: 200 {Success: true, FlowToken, Ctx}
  C->>E: POST /common/SAS/ProcessAuth (form)<br/>request, mfaAuthMethod (same value), login, flowToken, canary
  E-->>C: 302 code, or 200 interrupt HTML
'''
F['fig-10-fido-passwordless']='''sequenceDiagram
  autonumber
  participant C as Client
  participant K as FIDO authenticator<br/>(local, outside ESTS HTTP)
  participant E as ESTS<br/>login.microsoftonline.com
  participant EF as login.microsoft.com
  Note over C,E: GetCredentialType returned Credentials.FidoParams{AllowList, ...}<br/>(request flag isFidoSupported=true)
  C->>EF: POST {urlFidoLogin} (/{tenant}/fido/get?uiflavor=Host)<br/>browser User-Agent, flow=mfa, allowedIdentities, canary, serverChallenge, postBackUrl, postBackUrlAad,<br/>cancelUrl, resumeUrl, correlationId, credentialsJson=AllowList[0], ctx, username, loginCanary
  EF-->>C: 200 HTML with a new $Config<br/>sFidoChallenge, sCrossDomainCanary, sessionId, sFT, sCtx, canary, urlPost
  C->>K: challenge from sFidoChallenge
  K-->>C: WebAuthn assertion
  C->>E: POST {urlPost} (form)<br/>type=23, ps=23, assertion, lmcCanary=sCrossDomainCanary,<br/>hpgrequestid=sessionId, ctx, canary, flowToken
  alt code delivered
    E-->>C: 302 Location with code<br/>or 200 HTML whose anchor href carries code
  else interrupt or auto-submit
    E-->>C: 200 HTML (Figure 13, Figure 17)
  end
'''
F['fig-11-fido-from-tfa']='''sequenceDiagram
  autonumber
  participant C as Client
  participant K as FIDO authenticator<br/>(local)
  participant E as ESTS
  participant EF as login.microsoft.com
  C->>E: POST /{tenant}/login  (username and password, Figure 5)
  E-->>C: 200 pgid=ConvergedTFA<br/>arrUserProofs includes FidoKey<br/>Auth Config also contains arrFidoAllowList, urlFidoLogin, iAllowedIdentities, urlPost
  Note over C,E: BeginAuth is not used for FidoKey
  C->>EF: POST {urlFidoLogin}<br/>credentialsJson=arrFidoAllowList[0], other fields as in Figure 10
  EF-->>C: 200 HTML with a new $Config<br/>sFidoChallenge, sCrossDomainCanary, sessionId, sFT, sCtx, canary, urlPost
  C->>K: challenge
  K-->>C: assertion
  C->>E: POST {urlPost}: type=23, ps=23, assertion, lmcCanary, hpgrequestid, ctx, canary, flowToken
  E-->>C: 302 with code, 200 HTML anchor with code, or interrupt HTML
'''
F['fig-12-tap']='''sequenceDiagram
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
F['fig-13-interrupts']='''flowchart TB
  A["MFA success<br/>(ProcessAuth, passwordless login, FIDO or TAP post)"] --> B{"Response"}
  B -->|"302 / JS redirect / anchor<br/>with code"| T(["Authorization response (Figure 20)"])
  B -->|"200 HTML"| P{"Parse $Config pgid"}
  B -->|"auto-submit form<br/>(Working..., Click Submit to continue)"| AS["Auto-submit loop (Figure 17)"]
  P -->|"KmsiInterrupt"| K["POST urlPost with LoginOptions=1<br/>(Figure 14)"]
  P -->|"ConvergedProofUpRedirect<br/>with a skip or postponement option"| PU["POST advertised skip-resume URL<br/>or LoginOptions=1 if postponement is offered<br/>(Figure 15)"]
  P -->|"ConvergedChangePassword"| SS["SSPR begin, poll, confirm<br/>(Figure 16)"]
  P -->|"ConvergedConsent"| CO(["terminal for this protocol"])
  P -->|"unhandled error after checking pgid"| ER(["error (Figure 22)"])
  K --> B
  PU --> B
  AS --> B
  SS -->|"restart sign-in with new password"| R(["new authorize request"])
'''
F['fig-14-kmsi']='''sequenceDiagram
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
F['fig-15-proofup']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS<br/>login.microsoftonline.com
  participant R as mysignins.microsoft.com<br/>(registration, not specified)
  Note over C,E: After ProcessAuth or login: 200 pgid=ConvergedProofUpRedirect<br/>sErrorCode 50203, urlSkipMfaRegistration<br/>urlPost on the registration host, no sCtx
  alt registration required or chosen
    C-xR: register a method (out of scope)
  else skip (urlSkipMfaRegistration advertised)
    C->>E: POST /{tenant}/resume?skipmfaregistration=1 (form)<br/>flowtoken=sFT, ctx=request value posted to ProcessAuth, canary
    E-->>C: 302 Location with code and session_state<br/>+ authenticated cookies, CCState, SignInStateCookie
  else postponement days remain (iRemainingDaysToSkipMfaRegistration)
    C->>E: POST current urlPost: LoginOptions=1, ctx, flowToken (preceding page), canary (interrupt page)
    E-->>C: new $Config, 302 with code, or further interrupt
  end
'''
F['fig-16-sspr']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS
  Note over C,E: Password login returned pgid=ConvergedChangePassword<br/>urlAsyncSsprBegin, urlAsyncSsprPoll, urlPost (may be root-relative)
  C->>E: POST {urlAsyncSsprBegin} (JSON)<br/>{Ctx, FlowToken, OldPassword, NewPassword}
  E-->>C: 200 {IsJobPending: true, Ctx, FlowToken, CoupledDataCenter, CoupledScaleUnit, ErrorMessage}
  loop about once per second while IsJobPending is true
    C->>E: POST {urlAsyncSsprPoll} (JSON)<br/>{Ctx, FlowToken, CoupledDataCenter, CoupledScaleUnit}
    E-->>C: 200 {IsJobPending, Ctx, FlowToken, ..., ErrorMessage}
  end
  Note over C,E: Stop on non-null ErrorMessage. Confirm only after completion without error.
  C->>E: POST {urlPost} (JSON)<br/>{Ctx, FlowToken, currentpasswd, confirmnewpasswd, canary}
  E-->>C: HTTP success status
  Note over C,E: Restart interactive authentication with the new password<br/>(new authorize request, amr_values=ngcmfa omitted)
'''
F['fig-17-autosubmit']='''flowchart TB
  A["200 HTML response"] --> B{"Interstitial<br/>marker present?"}
  B -.- MK["Markers (substring match on body):<br/>Click Submit to continue<br/>Working...<br/>Click here to finish the authorization process<br/>input type=submit"]
  B -->|no| C{"Authorization response?<br/>(Figure 20)"}
  C -->|yes| T(["extract code"])
  C -->|no| P["Parse $Config<br/>(Figure 13 / Figure 22)"]
  B -->|yes| D["Parse first form<br/>resolve action against response URL"]
  D --> E["Collect enabled continuation inputs<br/>with name and value; preserve duplicates"]
  E --> F["POST to action<br/>(application/x-www-form-urlencoded)"]
  F -->|"next response"| B
'''
F['fig-18-device-code']='''sequenceDiagram
  autonumber
  participant C as Client
  participant E as ESTS (v2.0)
  participant B as User's browser<br/>(any device)
  C->>E: POST /{tenant|common}/oauth2/v2.0/devicecode<br/>client_id, scope=openid profile offline_access + resource scopes
  E-->>C: 200 {device_code, user_code, verification_uri, expires_in, interval, message}
  C-->>B: show verification_uri and user_code to the user
  B->>E: user signs in and completes MFA in a browser
  loop interval seconds (default 5), on slow_down add 5 seconds,<br/>stop on success, expiry or terminal error
    C->>E: POST /{tenant|common}/oauth2/v2.0/token<br/>client_id, grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code
    E-->>C: 400 {error: authorization_pending, error_codes: [70016]}
  end
  C->>E: POST /{tenant|common}/oauth2/v2.0/token (same request)
  E-->>C: 200 {access_token, refresh_token, id_token, expires_in (number), scope}
  Note over C,E: Validate the ID token and compare stable identity claims to the intended account
  opt redeem the refresh token for another resource
    C->>E: POST /{tenant}/oauth2/v2.0/token<br/>client_id, grant_type=refresh_token, refresh_token,<br/>scope=...{resource}/.default, client_info=1
    E-->>C: 200 token response
  end
'''
F['fig-19-consumers-federated']='''flowchart TB
  G["Credential discovery or later authentication response"] --> Q{"Which indicator?"}
  Q -->|"IfExistsResult 5<br/>(personal Microsoft account)"| C1["POST login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"]
  C1 --> C2["Show verification_uri (consumers host, for example www.microsoft.com/link)<br/>and user_code"]
  C2 --> C3["Poll POST /consumers/oauth2/v2.0/token<br/>until tokens or error"]
  C3 --> OUT(["tokens<br/>no token for enrollment.manage.microsoft.com"])
  Q -->|"Credentials.FederationRedirectUrl<br/>(external IdP)"| F1["Browser redirect to the external IdP<br/>not completed by the SAS / Remote NGC APIs"]
  F1 --> F2["Use another grant: device authorization grant<br/>POST /{tenant}/oauth2/v2.0/devicecode (Figure 18)"]
  Q -->|"AADSTS 50203, 16000, 50072<br/>(no advertised skip or postponement)"| F2
'''
F['fig-20-authz-response']='''flowchart TB
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
  X["Validate response target and state;<br/>accept code only on success"] -->|"code accepted"| TK["POST /{tenant}/oauth2/token<br/>client_id, grant_type=authorization_code,<br/>code, redirect_uri (identical to authorize)"]
  X -->|"error or invalid response binding"| REJECT(["Stop; do not redeem a code"])
  TK --> R{"Response"}
  R -->|"200 JSON"| OK(["access_token, refresh_token, id_token<br/>expires_in etc. as JSON strings (v1)"])
  R -->|"400 JSON error, error_description AADSTS..."| ER(["error (Figure 22)"])
'''
F['fig-21-token-lineage']='''flowchart TB
  subgraph AZ["authorize page ($Config)"]
    s1["sFT, sCtx, canary<br/>apiCanary, sessionId"]
  end
  s1 -->|"sFT, sCtx"| GCT["GetCredentialType<br/>flowToken, originalRequest"]
  s1 -->|"sFT, sCtx, canary"| GOT["GetOneTimeCode"]
  s1 -->|"canary"| DCS["DeviceCodeStatus polls<br/>(no flow token)"]
  s1 -->|"sFT, sCtx, canary<br/>+ SessionIdentifier"| LNGC["login (Remote NGC)"]
  s1 -->|"sFT, sCtx, canary"| LPW["login (password)"]
  LPW --> TFA
  subgraph TFA["ConvergedTFA page ($Config)"]
    s2["sFT, sCtx, canary, sessionId"]
  end
  s2 -->|"sFT, sCtx, canary"| BA["BeginAuth"]
  BA -->|"FlowToken, Ctx<br/>(reused on every poll)"| EA["EndAuth polls<br/>x-ms-flowToken, x-ms-ctx<br/>x-ms-sessionId = TFA sessionId"]
  EA -->|"final FlowToken, Ctx"| PA["ProcessAuth<br/>flowToken, request=Ctx<br/>canary from TFA page"]
  s2 -->|"canary"| PA
  PA --> PUP
  subgraph PUP["ProofUp page ($Config, no sCtx)"]
    s3["sFT, canary, sessionId"]
  end
  s3 -->|"sFT, canary"| RES["resume?skipmfaregistration=1<br/>flowtoken, canary"]
  PA -->|"ctx = request value posted to ProcessAuth"| RES
  RES -->|"302 code"| TK["token endpoint"]
'''
F['fig-22-errors']='''flowchart LR
  R["Any ESTS response"] --> K{"Channel"}
  K -->|"200 HTML with $Config"| A["sErrorCode / iErrorCode<br/>sErrTxt, strServiceExceptionMessage, arrValErrs<br/>(50058 on the first page is not an error)"]
  K -->|"SAS JSON"| B["Success false, Retry false<br/>ResultValue, Message, ErrCode"]
  K -->|"302 Location"| C["error and error_description<br/>(AADSTS{code}: ... Trace ID, Correlation ID, Timestamp)"]
  K -->|"token or devicecode JSON"| D["error, error_description,<br/>error_codes[], timestamp, trace_id, correlation_id"]
  A --> M{"Diagnostic AADSTS code<br/>(interpret with flow state)"}
  B --> M
  C --> M
  D --> M
  M -->|"50126, 50053"| M1(["credentials rejected or account locked"])
  M -->|"500121"| M2(["MFA not completed"])
  M -->|"50087"| M3(["transient SAS error: retry"])
  M -->|"50089"| M4(["flow token expired: restart"])
  M -->|"50076, 50074"| M5(["MFA required: new authorize request"])
  M -->|"50203, 50072, 50079, 16000"| M6(["registration / interaction required:<br/>use advertised skip; otherwise interactive flow"])
  M -->|"50055"| M7(["password change interrupt (Figure 16)"])
  M -->|"70016"| M8(["device flow pending: keep polling"])
  M -->|"54005, 70011, 700016, 65001, 53003"| M9(["code redeemed, scope, app or consent, Conditional Access"])
'''
F['fig-23-cookies']='''sequenceDiagram
  autonumber
  participant C as Client cookie jar
  participant E as ESTS
  C->>E: GET authorize (no cookies)
  E-->>C: Set-Cookie buid, esctx, esctx-A, fpc, stsservicecookie, x-ms-gateway-slice
  C->>E: GetCredentialType / GetOneTimeCode / DeviceCodeStatus (jar returned)
  E-->>C: Set-Cookie fpc, x-ms-gateway-slice
  C->>E: POST login (password or Remote NGC)
  E-->>C: Set-Cookie ESTSAUTH, ESTSAUTHPERSISTENT, ESTSAUTHLIGHT, new buid, esctx, esctx-B<br/>delete esctx-A (empty value, past expiry)<br/>Remote NGC: also CCState, SignInStateCookie (code issued)
  Note over C,E: Password path: these are present before MFA completes<br/>and are not proof of authentication
  C->>E: SAS BeginAuth / EndAuth polls (jar returned)
  E-->>C: Set-Cookie fpc, x-ms-gateway-slice
  C->>E: POST ProcessAuth
  E-->>C: re-issue ESTSAUTH*, buid, esctx, esctx-C<br/>delete esctx-B
  C->>E: POST resume
  E-->>C: re-issue auth cookies, CCState, SignInStateCookie<br/>delete esctx-C, 302 with code
  C->>E: POST /{tenant}/oauth2/token
  E-->>C: Set-Cookie fpc, x-ms-gateway-slice only
'''
F['fig-24-v1-v2']='''flowchart TB
  subgraph V1["v1 endpoints: interactive MFA API surface"]
    direction TB
    a1["GET /{tenant}/oauth2/authorize<br/>resource, amr_values=ngcmfa,<br/>caller_app_*, sso_reload"]
    a1 --> AC["Auth Config pages<br/>follow-on APIs use advertised URLs (absolute or relative)<br/>with no endpoint-version marker"]
    AC --> a2["POST /{tenant}/oauth2/token<br/>client_id, grant_type, code, redirect_uri"]
  end
  subgraph V2["v2.0 endpoints"]
    direction TB
    b1["GET /{tenant}/oauth2/v2.0/authorize<br/>scope, code_challenge, state, nonce, domain_hint<br/>ngcmfa and caller_app_* behavior unverified"]
    b3["POST /{tenant}/oauth2/v2.0/devicecode"]
    b1 -->|"interactive or silent authorization"| b2["POST /{tenant}/oauth2/v2.0/token<br/>authorization_code, refresh_token,<br/>password, device_code grants"]
    b3 --> b2
  end
  a2 --> T1(["Access token version is chosen by the target resource<br/>(ver 1.0 or 2.0), not by the endpoint"])
  b2 --> T1
'''

import re as _re
_REMAP={1: 1, 3: 2, 2: 3, 4: 4, 5: 5, 12: 6, 10: 7, 6: 8, 7: 9, 8: 10, 9: 11, 11: 12, 13: 13, 14: 14, 15: 15, 16: 16, 17: 17, 19: 18, 18: 19, 24: 20, 21: 21, 23: 22, 22: 23, 20: 24}
for _k in list(F):
    F[_k]=F[_k].replace('Figure 13 / 22','Figure 13 / Figure 22')
    F[_k]=_re.sub(r'Figure (\d+)',lambda m:'Figure %d'%_REMAP[int(m.group(1))],F[_k])
_new={}
for _k,_v in F.items():
    _n=int(_k.split('-')[1]); _new['fig-%02d-%s'%(_REMAP[_n],_k.split('-',2)[2])]=_v
F=_new

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
            out.append('%s%s poll'%(m.group(1),m.group(2)) if m.group(2)=='loop' else '%sopt details'%m.group(1))
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
    if F[k].startswith('sequenceDiagram'): F[k]=fix_seq(F[k])
from pathlib import Path
source_dir = Path(__file__).resolve().parent / 'src'
source_dir.mkdir(parents=True, exist_ok=True)
for k,v in F.items():
    (source_dir / ('%s.mmd' % k)).write_text(v, encoding='utf-8')
print(len(F))
