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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Parsing-contract tests for the push-token {@code /validate/*} surface, driven directly through the wire parser
 * ({@link JSONParser#parsePIResponse(String)}). The response bodies are taken verbatim from the privacyIDEA
 * test-driven documentation in {@code validate-doc/push.md} (captured against the 3.14 cycle).
 * <p>
 * The focus is the contract the Keycloak provider relies on to route a challenge: {@code preferredClientMode},
 * {@link PIResponse#pushAvailable()}, {@link PIResponse#pushTransactionId()} and {@link PIResponse#otpTransactionId()}.
 * In particular {@code push_code_to_phone} (a push challenge with {@code client_mode=interactive}) must surface its
 * transaction id via {@link PIResponse#otpTransactionId()} so the entered code is finalized together with that
 * transaction instead of being treated as a fresh PIN.
 */
public class TestPushValidate
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
     * Standard poll-mode push challenge (validate-doc/push.md PushChallengeTags::test_01).
     * The provider routes this to PUSH/polling: pushAvailable, the push transaction id is set, and there is no OTP
     * transaction id (no interactive input field is shown).
     */
    @Test
    public void testStandardPollPushChallenge()
    {
        PIResponse r = parser.parsePIResponse(pollPushChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertFalse(r.value);
        assertTrue(r.hasChallenges());
        assertEquals(1, r.multiChallenge.size());
        assertEquals("push", r.type);
        // "poll" is translated to the provider-side mode name "push"
        assertEquals("push", r.preferredClientMode);
        assertTrue(r.pushAvailable());
        assertEquals("16860228690071227067", r.pushTransactionId());
        assertNull(r.otpTransactionId());
    }

    /**
     * push_code_to_phone: a push challenge delivered with client_mode=interactive (validate-doc/push.md
     * test_17_push_code_to_phone, call 1). REGRESSION GUARD for the code_to_phone fix:
     * <ul>
     *   <li>pushAvailable() must be false (interactive, not poll) so the provider does not enter the polling path,</li>
     *   <li>otpTransactionId() must return the transaction id so the typed code is submitted together with it,</li>
     *   <li>preferredClientMode "interactive" is translated to "otp" -> the provider renders an input field.</li>
     * </ul>
     */
    @Test
    public void testCodeToPhoneInteractiveChallenge()
    {
        PIResponse r = parser.parsePIResponse(codeToPhoneChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertFalse(r.value);
        assertTrue(r.hasChallenges());
        assertEquals(1, r.multiChallenge.size());
        // "interactive" is translated to the provider-side mode name "otp" -> Mode.OTP, input field shown
        assertEquals("otp", r.preferredClientMode);
        // Interactive push is not a poll challenge, so it must NOT be treated as a pollable push
        assertFalse(r.pushAvailable());
        // The fix: the interactive push challenge exposes its transaction id as the OTP transaction id so that the
        // code the user types is finalized with this transaction (previously this returned null -> "wrong otp pin").
        assertEquals("00110530786071310297", r.otpTransactionId());
        // It is still recognized as a push transaction by type
        assertEquals("00110530786071310297", r.pushTransactionId());
        assertEquals("Please enter the code displayed on your smartphone.", r.message);
    }

    /**
     * push_code_to_phone finalize with the correct display code (validate-doc/push.md test_17, call 2).
     */
    @Test
    public void testCodeToPhoneFinalizeAccept()
    {
        PIResponse r = parser.parsePIResponse(foundMatchingChallengeAccept());

        assertTrue(r.value);
        assertFalse(r.hasChallenges());
        assertTrue(r.authenticationSuccessful());
        assertEquals("Found matching challenge", r.message);
    }

    /**
     * push_code_to_phone finalize with the wrong code (validate-doc/push.md test_18, call 2).
     */
    @Test
    public void testCodeToPhoneFinalizeReject()
    {
        PIResponse r = parser.parsePIResponse(responseDidNotMatch());

        assertEquals(AuthenticationStatus.REJECT, r.authentication);
        assertFalse(r.value);
        assertFalse(r.authenticationSuccessful());
        assertFalse(r.hasChallenges());
        assertEquals("Response did not match the challenge.", r.message);
        assertEquals("push", r.type);
    }

    /**
     * push_require_presence: poll-mode challenge that embeds the presence letter in the message
     * (validate-doc/push.md test_15, call 1). Routed to push/polling, not to an interactive input.
     */
    @Test
    public void testRequirePresenceChallenge()
    {
        PIResponse r = parser.parsePIResponse(requirePresenceChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertEquals("push", r.preferredClientMode);
        assertTrue(r.pushAvailable());
        assertEquals("01160757231600984930", r.pushTransactionId());
        assertNull(r.otpTransactionId());
        assertTrue(r.message.contains("Please press: L"));
    }

    /**
     * push_code_to_phone combined with push_require_presence: require_presence wins, so the challenge comes back in
     * poll mode (NOT interactive) (validate-doc/push.md test_19, call 1). This guards that the code_to_phone fix does
     * not misfire here: because client_mode is poll, otpTransactionId() must stay null and the flow stays a poll push.
     */
    @Test
    public void testCodeToPhoneRequirePresenceWinsStaysPoll()
    {
        PIResponse r = parser.parsePIResponse(codeToPhoneRequirePresenceChallenge());

        assertEquals("push", r.preferredClientMode);
        assertTrue(r.pushAvailable());
        assertEquals("15192793174567139480", r.pushTransactionId());
        // require_presence wins -> poll mode -> this is NOT an interactive code_to_phone challenge
        assertNull(r.otpTransactionId());
        assertTrue(r.message.contains("Please press: T"));
    }

    /**
     * push_wait timing out (validate-doc/push.md test_16 / test_20): a plain REJECT with "wrong otp value" and no
     * challenges. This is the message a user sees when no smartphone confirmation arrives in the wait window.
     */
    @Test
    public void testPushWaitReject()
    {
        PIResponse r = parser.parsePIResponse(wrongOtpValueReject());

        assertEquals(AuthenticationStatus.REJECT, r.authentication);
        assertFalse(r.value);
        assertFalse(r.hasChallenges());
        assertFalse(r.authenticationSuccessful());
        assertEquals("wrong otp value", r.message);
        assertEquals(6, r.otpLength);
        assertEquals("push", r.type);
    }

    /**
     * enroll_via_multichallenge=push: the enrollment QR challenge (validate-doc/push.md test_10, call 2).
     * Poll-mode push carrying the enrollment image/link and the enroll_via_multichallenge marker.
     */
    @Test
    public void testEnrollViaMultichallengePush()
    {
        PIResponse r = parser.parsePIResponse(enrollViaMultichallengePush());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertTrue(r.isEnrollViaMultichallenge);
        assertFalse(r.isEnrollViaMultichallengeOptional);
        assertTrue(r.pushAvailable());
        assertEquals("04735287467914993762", r.pushTransactionId());
        // The enrollment challenge carries no preferred_client_mode; the provider falls back to push via pushAvailable()
        assertEquals("", r.preferredClientMode);
    }

    // --- Response bodies taken from validate-doc/push.md (envelope fields trimmed) ---

    private static String pollPushChallenge()
    {
        return "{\"detail\":{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device!\"," +
               "\"messages\":[\"Please confirm the authentication on your mobile device!\"]," +
               "\"multi_challenge\":[{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device!\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"16860228690071227067\"," +
               "\"type\":\"push\"}]," +
               "\"preferred_client_mode\":\"poll\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"16860228690071227067\"," +
               "\"transaction_ids\":[\"16860228690071227067\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String codeToPhoneChallenge()
    {
        return "{\"detail\":{" +
               "\"attributes\":{\"hideResponseInput\":false}," +
               "\"client_mode\":\"interactive\"," +
               "\"message\":\"Please enter the code displayed on your smartphone.\"," +
               "\"messages\":[\"Please enter the code displayed on your smartphone.\"]," +
               "\"multi_challenge\":[{" +
               "\"attributes\":{\"hideResponseInput\":false}," +
               "\"client_mode\":\"interactive\"," +
               "\"message\":\"Please enter the code displayed on your smartphone.\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"00110530786071310297\"," +
               "\"type\":\"push\"}]," +
               "\"preferred_client_mode\":\"interactive\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"00110530786071310297\"," +
               "\"transaction_ids\":[\"00110530786071310297\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String foundMatchingChallengeAccept()
    {
        return "{\"detail\":{" +
               "\"message\":\"Found matching challenge\"," +
               "\"serial\":\"PIPU001\"}," +
               "\"result\":{\"authentication\":\"ACCEPT\",\"status\":true,\"value\":true}}";
    }

    private static String responseDidNotMatch()
    {
        return "{\"detail\":{" +
               "\"message\":\"Response did not match the challenge.\"," +
               "\"serial\":\"PIPU001\"," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"REJECT\",\"status\":true,\"value\":false}}";
    }

    private static String requirePresenceChallenge()
    {
        return "{\"detail\":{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device! Please press: L\"," +
               "\"messages\":[\"Please confirm the authentication on your mobile device! Please press: L\"]," +
               "\"multi_challenge\":[{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device! Please press: L\"," +
               "\"presence_answer\":\"L\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"01160757231600984930\"," +
               "\"type\":\"push\"}]," +
               "\"preferred_client_mode\":\"poll\"," +
               "\"presence_answer\":\"L\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"01160757231600984930\"," +
               "\"transaction_ids\":[\"01160757231600984930\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String codeToPhoneRequirePresenceChallenge()
    {
        return "{\"detail\":{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device! Please press: T\"," +
               "\"messages\":[\"Please confirm the authentication on your mobile device! Please press: T\"]," +
               "\"multi_challenge\":[{" +
               "\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device! Please press: T\"," +
               "\"presence_answer\":\"T\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"15192793174567139480\"," +
               "\"type\":\"push\"}]," +
               "\"preferred_client_mode\":\"poll\"," +
               "\"presence_answer\":\"T\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"15192793174567139480\"," +
               "\"transaction_ids\":[\"15192793174567139480\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String wrongOtpValueReject()
    {
        return "{\"detail\":{" +
               "\"message\":\"wrong otp value\"," +
               "\"otplen\":6," +
               "\"serial\":\"PIPU001\"," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"REJECT\",\"status\":true,\"value\":false}}";
    }

    private static String enrollViaMultichallengePush()
    {
        return "{\"detail\":{" +
               "\"client_mode\":\"poll\"," +
               "\"enroll_via_multichallenge\":true," +
               "\"enroll_via_multichallenge_optional\":false," +
               "\"image\":\"data:image/png;base64,AAAA\"," +
               "\"link\":\"otpauth://pipush/Pushy?url=http%3A//test/ttype/push&ttl=10\"," +
               "\"message\":\"Please scan the QR code!\"," +
               "\"multi_challenge\":[{" +
               "\"client_mode\":\"poll\"," +
               "\"image\":\"data:image/png;base64,AAAA\"," +
               "\"link\":\"otpauth://pipush/Pushy?url=http%3A//test/ttype/push&ttl=10\"," +
               "\"message\":\"Please scan the QR code!\"," +
               "\"serial\":\"PIPU00003CF0\"," +
               "\"transaction_id\":\"04735287467914993762\"," +
               "\"type\":\"push\"}]," +
               "\"serial\":\"PIPU00003CF0\"," +
               "\"transaction_id\":\"04735287467914993762\"," +
               "\"transaction_ids\":[\"04735287467914993762\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }
}
