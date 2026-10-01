# Changelog

### 1.6.0 - 1 October 2026
* Updated the bundled OkHttp to 5.4.0, kotlin-stdlib to 2.4.0 and okio to 3.18.2. OkHttp and okio are now
  referenced by their `-jvm` artifacts: OkHttp 5 is a Kotlin Multiplatform release whose plain `okhttp` artifact
  carries no classes for Maven builds.
* java-jwt is now a test-only dependency, so neither it nor the Jackson libraries it pulls in are part of the
  client's dependency tree anymore.
* Capture the remember-device cookie on WebAuthn and passkey authentications (previously only the OTP path
  propagated the Set-Cookie, so "remember this device" silently did nothing with a security key / passkey).
* Add a getTokenInfo(username, headers) overload so callers can forward request headers on GET /token
  (the existing getTokenInfo(username) delegates to it with no headers).
* Improved logging hygiene: the Authorization token, the `X-API-Key`, and token seeds/OTP values are no longer
  written to the log, and logged values are sanitized to prevent forged log lines.
* Requests are now executed synchronously per call; the internal fixed-size thread pool was removed, so the
  number of concurrent requests is bounded by the caller (the host application's request threads) instead of a
  hard limit. The HTTP timeout now bounds each call in full.
* More robust response parsing: malformed or unexpectedly-typed server responses (e.g. HTML error pages) no
  longer throw; they yield a clear error or a safe default. `pollTransaction` returns `ChallengeStatus.none`
  on transport failures instead of throwing.
* Fixed request parameter encoding so values containing reserved characters are no longer double-encoded.
* JWT retrieval now recovers from a transient failed refresh instead of stopping permanently.
* Redirects are no longer followed — the client only talks to the configured server URL.
* Added remember-device support: `/validate/capabilities` capability lookup, `Set-Cookie` propagation on the
  response, and a `validateCheckPasskey` overload that accepts additional parameters.
* `close()` now releases the underlying HTTP resources; the builder validates required parameters.

### 1.5.1 - 30 June 2026
* Fixed PIResponse::otpTransactionId() to also return the transaction id for push/smartphone challenges in
  interactive mode (push_code_to_phone). Previously it returned none for these, so the code entered by the user was
  validated without the transaction id and rejected. This completes the interactive-push handling introduced in 1.5.0.
* Added a test suite for the push, challenge-response/multichallenge and passkey /validate/* response shapes.

### 1.5.0 - 26 March 2026
* Adjusted several functions to differentiate between push token in interactive mode (push_code_to_phone in privacyIDEA 3.13)
    For example PIResponse::OtpMessage() will only return messages of challenges that have the client_mode 'interactive'.

### 1.4.0 - 21 May 2025

* PIResponse class can return the transaction based on the mode/type, which currently are Push, WebAuthn, Passkey and OTP.
* HTTP request headers are logged
* WebAuthn class as derived class of Challenge has been removed to allow simple serialization of PIResponse
* allowCredentials for WebAuthnSignRequests are merged when the PIResponse object is created and the combined SignRequest
  is set to PIResponse.webAuthnSignRequest. WebAuthn challenges are not in the multi_challenge list anymore!

### v1.3.1 - 14 May 2025

* PIResponse::isAuthenticationSuccessful will also consider if multi_challenge is present, not just the authentication field

### v1.3.0 - 8 Apr 2025

* Passkey functions
* JWT will be reused and renewed automatically
* Added option to add arbitrary parameters to the requests
* Added enrollmentLink to PIResponse for enroll_via_multichallenge responses

### v1.2.2 - 5 Mar 2024

* Fixed a problem with the thread pool where thread would not time out and accumulate over time
* Added the option to set http timeouts

### v1.2.1 - 9 Aug 2023

* Added Kotlin dependencies for okhttp

### v1.2.0 - 17 Jan 2023

* Added implementation of a new feature: Token enrollment via challenge (#47)
* Added implementation of the preferred client mode (#42, #49)

### v1.0.2 - 06 May 2022

* Added option to pass headers to every privacyIDEA API function

### v1.0.1 - 25 Mar 2022

* Merge sign request for multiple WebAuthn tokens (#31)
* Add authentication status to PIResponse (#32)
* Add error to responses (#27)

### v1.0.0 - 12 Oct 2021

* Add U2F support (#25)

### v0.3 - 26 Apr 2021

* Using async requests (#22)

### v0.2 - 05 Feb 2021

* Add WebAuthn support (#18)
* Add trigger challenge
* Add token enrollment
* Add push token support

### v0.1 - 18 Sep 2020

* First version
* Supports basic OTP token