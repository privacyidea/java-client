# Changelog

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
