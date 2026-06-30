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
 * Parsing-contract tests for the generic challenge-response / multichallenge {@code /validate/*} surface, driven
 * through the wire parser ({@link JSONParser#parsePIResponse(String)}). Bodies are taken from
 * {@code validate-doc/challenge-response.md} and {@code validate-doc/multichallenge.md}.
 * <p>
 * These pin the transaction-id routing the Keycloak provider depends on: {@link PIResponse#otpTransactionId()} for
 * interactive (input-field) tokens vs. {@link PIResponse#pushTransactionId()} for pollable push tokens, and how the
 * translated {@code preferredClientMode} selects the provider mode.
 */
public class TestChallengeResponseParsing
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
     * Plain HOTP challenge-response (validate-doc/challenge-response.md, call 1): a single interactive token.
     * otpTransactionId() carries the transaction; there is no push.
     */
    @Test
    public void testInteractiveOtpChallenge()
    {
        PIResponse r = parser.parsePIResponse(hotpChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertFalse(r.value);
        assertTrue(r.hasChallenges());
        // "interactive" -> provider mode "otp"
        assertEquals("otp", r.preferredClientMode);
        assertFalse(r.pushAvailable());
        assertEquals("08954727052769857579", r.otpTransactionId());
        assertNull(r.pushTransactionId());
    }

    /**
     * Mixed HOTP + poll-push challenge sharing one transaction id (validate-doc/multichallenge.md test_03).
     * Both accessors must resolve to the shared transaction id, push is available, and preferred mode is push (poll).
     */
    @Test
    public void testMixedOtpAndPushChallenge()
    {
        PIResponse r = parser.parsePIResponse(mixedHotpAndPushChallenge());

        assertEquals(AuthenticationStatus.CHALLENGE, r.authentication);
        assertEquals(2, r.multiChallenge.size());
        assertTrue(r.pushAvailable());
        // "poll" -> provider mode "push"
        assertEquals("push", r.preferredClientMode);
        // Interactive HOTP part is reachable via otpTransactionId, push part via pushTransactionId
        assertEquals("02108856971392266777", r.otpTransactionId());
        assertEquals("02108856971392266777", r.pushTransactionId());
    }

    /**
     * Answering the OTP under the transaction id (validate-doc/challenge-response.md, call 2).
     */
    @Test
    public void testChallengeResponseAccept()
    {
        PIResponse r = parser.parsePIResponse(foundMatchingChallenge());

        assertTrue(r.value);
        assertTrue(r.authenticationSuccessful());
        assertFalse(r.hasChallenges());
        assertEquals("Found matching challenge", r.message);
    }

    private static String hotpChallenge()
    {
        return "{\"detail\":{" +
               "\"client_mode\":\"interactive\"," +
               "\"message\":\"please enter otp: \"," +
               "\"messages\":[\"please enter otp: \"]," +
               "\"multi_challenge\":[{" +
               "\"client_mode\":\"interactive\"," +
               "\"message\":\"please enter otp: \"," +
               "\"serial\":\"hotp1\"," +
               "\"transaction_id\":\"08954727052769857579\"," +
               "\"type\":\"hotp\"}]," +
               "\"preferred_client_mode\":\"interactive\"," +
               "\"serial\":\"hotp1\"," +
               "\"transaction_id\":\"08954727052769857579\"," +
               "\"transaction_ids\":[\"08954727052769857579\"]," +
               "\"type\":\"hotp\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String mixedHotpAndPushChallenge()
    {
        return "{\"detail\":{" +
               "\"message\":\"Please confirm the authentication on your mobile device!, please enter otp: \"," +
               "\"messages\":[\"please enter otp: \",\"Please confirm the authentication on your mobile device!\"]," +
               "\"multi_challenge\":[{" +
               "\"client_mode\":\"interactive\"," +
               "\"message\":\"please enter otp: \"," +
               "\"serial\":\"CR2A\"," +
               "\"transaction_id\":\"02108856971392266777\"," +
               "\"type\":\"hotp\"}," +
               "{\"attributes\":{\"hideResponseInput\":true}," +
               "\"client_mode\":\"poll\"," +
               "\"message\":\"Please confirm the authentication on your mobile device!\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"02108856971392266777\"," +
               "\"type\":\"push\"}]," +
               "\"preferred_client_mode\":\"poll\"," +
               "\"serial\":\"PIPU001\"," +
               "\"transaction_id\":\"02108856971392266777\"," +
               "\"transaction_ids\":[\"02108856971392266777\",\"02108856971392266777\"]," +
               "\"type\":\"push\"}," +
               "\"result\":{\"authentication\":\"CHALLENGE\",\"status\":true,\"value\":false}}";
    }

    private static String foundMatchingChallenge()
    {
        return "{\"detail\":{" +
               "\"message\":\"Found matching challenge\"," +
               "\"serial\":\"hotp1\"}," +
               "\"result\":{\"authentication\":\"ACCEPT\",\"status\":true,\"value\":true}}";
    }
}
