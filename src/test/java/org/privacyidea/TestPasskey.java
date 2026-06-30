/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
 * - Modified
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import java.util.Map;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the passkey (FIDO2 resident key) surface, driven through the wire parser
 * ({@link JSONParser#parsePIResponse(String)}) and the FIDO2 request-param builders. Bodies are taken from the
 * privacyIDEA test-driven documentation in {@code validate-doc/passkey.md}.
 * <p>
 * Scope mirrors what the Keycloak provider actually uses: {@code validateInitialize("passkey")} (the challenge),
 * {@code validateCheckPasskey} (assertion -> username/ACCEPT or REJECT), {@code validateCheckCompletePasskeyRegistration}
 * (enroll_via_multichallenge), and the passkey challenge surfaced via the regular challenge path
 * (passkey_trigger_with_pin). The offline {@code auth_items} refill block is intentionally not covered — the provider
 * does not use offline.
 */
public class TestPasskey
{
    private JSONParser parser;

    @Before
    public void setup()
    {
        PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                             .verifySSL(false)
                                             .logger(new PILogImplementation())
                                             .build();
        parser = new JSONParser(privacyIDEA);
    }

    /**
     * validateInitialize(type=passkey): an unbound challenge carried in detail.passkey
     * (validate-doc/passkey.md test_01, call 1). The provider reads passkeyChallenge + transactionID from this.
     */
    @Test
    public void testValidateInitializePasskeyChallenge()
    {
        PIResponse r = parser.parsePIResponse(initializePasskeyChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertFalse(r.value);
        assertTrue(r.hasChallenges());
        // The whole detail.passkey object is exposed as the passkey challenge json passed to the browser
        assertTrue(r.passkeyChallenge.contains("SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0"));
        assertEquals("Please authenticate with your passkey!", r.passkeyMessage);
        assertEquals("12052838135417104562", r.transactionID);
        // A passkey challenge is not part of the multiChallenge / OTP / push routing
        assertTrue(r.multiChallenge.isEmpty());
        assertNull(r.otpTransactionId());
        assertNull(r.pushTransactionId());
    }

    /**
     * Answering the assertion successfully (validate-doc/passkey.md test_01, call 2): the response carries the
     * resolved username, which the provider uses to set the Keycloak user.
     */
    @Test
    public void testPasskeyAuthenticationAccept()
    {
        PIResponse r = parser.parsePIResponse(passkeyAuthAccept());

        assertTrue(r.value);
        assertTrue(r.authenticationSuccessful());
        assertEquals("hans", r.username);
        assertEquals("PIPK00000C99", r.serial);
    }

    /**
     * A rejected assertion (validate-doc/passkey.md test_03): no username, not successful.
     */
    @Test
    public void testPasskeyAuthenticationReject()
    {
        PIResponse r = parser.parsePIResponse(passkeyAuthReject());

        assertEquals(AuthenticationStatus.REJECT, r.authentication);
        assertFalse(r.value);
        assertFalse(r.authenticationSuccessful());
        assertEquals("", r.username);
        assertEquals("Authentication failed.", r.message);
    }

    /**
     * enroll_via_multichallenge=PASSKEY (validate-doc/passkey.md test_08, call 1): a CHALLENGE carrying a
     * passkey_registration payload that the provider hands to the browser to create the credential.
     */
    @Test
    public void testEnrollViaMultichallengePasskeyRegistration()
    {
        PIResponse r = parser.parsePIResponse(enrollViaMultichallengePasskey());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertTrue(r.isEnrollViaMultichallenge);
        assertFalse(r.isEnrollViaMultichallengeOptional);
        assertFalse(r.passkeyRegistration.isEmpty());
        assertTrue(r.passkeyRegistration.contains("pubKeyCredParams"));
        assertEquals("09946345496043966598", r.transactionID);
    }

    /**
     * passkey_trigger_with_pin (validate-doc/passkey.md test_05/06): a regular /validate/check returns a passkey
     * challenge as a multi_challenge entry of type "passkey"; the parser surfaces it as passkeyChallenge and does not
     * add it to the OTP multiChallenge list.
     */
    @Test
    public void testPasskeyTriggeredByPinChallenge()
    {
        PIResponse r = parser.parsePIResponse(passkeyTriggerByPinChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertFalse(r.passkeyChallenge.isEmpty());
        assertTrue(r.passkeyChallenge.contains("SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0"));
        assertEquals("05830065563488214401", r.transactionID);
        assertEquals("webauthn", r.preferredClientMode);
        assertTrue(r.multiChallenge.isEmpty());
    }

    /**
     * The browser assertion JSON is decomposed into the flat params privacyIDEA expects on /validate/check.
     */
    @Test
    public void testParseFIDO2AuthenticationResponseFull()
    {
        Map<String, String> params = parser.parseFIDO2AuthenticationResponse(fido2AuthenticationResponse());

        assertEquals("cred-1", params.get("credential_id"));
        assertEquals("client-data", params.get("clientDataJSON"));
        assertEquals("sig", params.get("signature"));
        assertEquals("auth-data", params.get("authenticatorData"));
        assertEquals("user-handle", params.get("userHandle"));
        assertEquals("ext", params.get("assertionclientextensions"));
    }

    /**
     * userHandle and assertionclientextensions are optional and must be omitted (not sent as empty) when absent.
     */
    @Test
    public void testParseFIDO2AuthenticationResponseOptionalFieldsOmitted()
    {
        Map<String, String> params = parser.parseFIDO2AuthenticationResponse(
                "{\"credential_id\":\"cred-1\",\"clientDataJSON\":\"client-data\"," +
                "\"signature\":\"sig\",\"authenticatorData\":\"auth-data\"}");

        assertTrue(params.containsKey("credential_id"));
        assertTrue(params.containsKey("authenticatorData"));
        assertFalse(params.containsKey("userHandle"));
        assertFalse(params.containsKey("assertionclientextensions"));
    }

    @Test
    public void testParseFIDO2AuthenticationResponseMalformedReturnsNull()
    {
        assertNull(parser.parseFIDO2AuthenticationResponse("{not valid json"));
    }

    /**
     * The browser attestation JSON is decomposed into the flat params for completing a passkey registration.
     */
    @Test
    public void testParseFIDO2RegistrationResponseFull()
    {
        Map<String, String> params = parser.parseFIDO2RegistrationResponse(fido2RegistrationResponse());

        assertEquals("cred-1", params.get("credential_id"));
        assertEquals("client-data", params.get("clientDataJSON"));
        assertEquals("attestation", params.get("attestationObject"));
        assertEquals("cross-platform", params.get("authenticatorAttachment"));
        assertEquals("raw-1", params.get("rawId"));
    }

    @Test
    public void testParseFIDO2RegistrationResponseMalformedReturnsNull()
    {
        assertNull(parser.parseFIDO2RegistrationResponse("not json at all"));
    }

    private static String initializePasskeyChallenge()
    {
        return "{\"detail\":{" +
               "\"passkey\":{" +
               "\"challenge\":\"SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0\"," +
               "\"message\":\"Please authenticate with your passkey!\"," +
               "\"rpId\":\"cool.nils\"," +
               "\"transaction_id\":\"12052838135417104562\"," +
               "\"user_verification\":\"preferred\"}," +
               "\"transaction_id\":\"12052838135417104562\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String passkeyAuthAccept()
    {
        return "{\"detail\":{" +
               "\"message\":\"Found matching challenge\"," +
               "\"serial\":\"PIPK00000C99\"," +
               "\"username\":\"hans\"}," +
               "\"result\":{\"authentication\":\"ACCEPT\",\"status\":true,\"value\":true}}";
    }

    private static String passkeyAuthReject()
    {
        return "{\"detail\":{\"message\":\"Authentication failed.\"}," +
               "\"result\":{\"authentication\":\"REJECT\",\"status\":true,\"value\":false}}";
    }

    private static String enrollViaMultichallengePasskey()
    {
        return "{\"detail\":{" +
               "\"client_mode\":\"webauthn\"," +
               "\"enroll_via_multichallenge\":true," +
               "\"enroll_via_multichallenge_optional\":false," +
               "\"message\":\"Please confirm the registration with your passkey!\"," +
               "\"multi_challenge\":[{" +
               "\"passkey_registration\":{" +
               "\"attestation\":\"none\"," +
               "\"authenticatorSelection\":{\"requireResidentKey\":true,\"residentKey\":\"required\",\"userVerification\":\"preferred\"}," +
               "\"challenge\":\"BF234MmliMJh6LW5Ab88Pn-dMJVGJ660KnRa3fFwNVQ\"," +
               "\"excludeCredentials\":[]," +
               "\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}]," +
               "\"rp\":{\"id\":\"cool.nils\",\"name\":\"cool.nils\"}," +
               "\"timeout\":12000," +
               "\"user\":{\"displayName\":\"hans\",\"id\":\"F85o6MXihU61SYIv\",\"name\":\"hans\"}}," +
               "\"rollout_state\":\"clientwait\"," +
               "\"serial\":\"PIPK00001285\"," +
               "\"transaction_id\":\"09946345496043966598\"," +
               "\"type\":\"passkey\"}]," +
               "\"serial\":\"PIPK00001285\"," +
               "\"transaction_id\":\"09946345496043966598\"," +
               "\"transaction_ids\":[\"09946345496043966598\"]," +
               "\"type\":\"passkey\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String passkeyTriggerByPinChallenge()
    {
        return "{\"detail\":{" +
               "\"challenge\":\"SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0\"," +
               "\"client_mode\":\"webauthn\"," +
               "\"message\":\"test text\"," +
               "\"messages\":[\"test text\"]," +
               "\"multi_challenge\":[{" +
               "\"challenge\":\"SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0\"," +
               "\"client_mode\":\"webauthn\"," +
               "\"message\":\"test text\"," +
               "\"rpId\":\"cool.nils\"," +
               "\"serial\":\"PIPK00002408\"," +
               "\"transaction_id\":\"05830065563488214401\"," +
               "\"type\":\"passkey\"," +
               "\"userVerification\":\"discouraged\"}]," +
               "\"preferred_client_mode\":\"webauthn\"," +
               "\"rpId\":\"cool.nils\"," +
               "\"serial\":\"PIPK00002408\"," +
               "\"transaction_id\":\"05830065563488214401\"," +
               "\"transaction_ids\":[\"05830065563488214401\"]," +
               "\"type\":\"passkey\"," +
               "\"userVerification\":\"discouraged\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String fido2AuthenticationResponse()
    {
        return "{\"credential_id\":\"cred-1\"," +
               "\"clientDataJSON\":\"client-data\"," +
               "\"signature\":\"sig\"," +
               "\"authenticatorData\":\"auth-data\"," +
               "\"userHandle\":\"user-handle\"," +
               "\"assertionclientextensions\":\"ext\"}";
    }

    private static String fido2RegistrationResponse()
    {
        return "{\"credential_id\":\"cred-1\"," +
               "\"clientDataJSON\":\"client-data\"," +
               "\"attestationObject\":\"attestation\"," +
               "\"authenticatorAttachment\":\"cross-platform\"," +
               "\"rawId\":\"raw-1\"}";
    }
}
