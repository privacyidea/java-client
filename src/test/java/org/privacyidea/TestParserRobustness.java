/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
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

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Robustness tests for {@link JSONParser}: malformed or unexpectedly-typed server responses must degrade
 * gracefully (null / partial object / synthetic error) instead of throwing uncaught RuntimeExceptions that
 * propagate to callers. Each test corresponds to a finding from the java-client audit.
 */
public class TestParserRobustness
{
    private JSONParser parser;
    private PrivacyIDEA privacyIDEA;

    @Before
    public void setup()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();
        parser = new JSONParser(privacyIDEA);
    }

    // M2 — nested wrong-typed fields must not throw; return a response carrying the synthetic error.
    @Test
    public void resultAsStringYieldsError()
    {
        PIResponse r = parser.parsePIResponse("{\"result\":\"denied\"}");
        assertNotNull(r);
        assertNotNull(r.error);
        assertEquals(PIConstants.CLIENT_ERROR_CODE, r.error.code);
    }

    @Test
    public void multiChallengePrimitiveElementYieldsError()
    {
        String body = "{\"detail\":{\"multi_challenge\":[42]},\"result\":{\"status\":true,\"value\":false}}";
        PIResponse r = parser.parsePIResponse(body);
        assertNotNull(r);
        assertNotNull(r.error);
        assertEquals(PIConstants.CLIENT_ERROR_CODE, r.error.code);
    }

    // L8 — a JSON null inside the messages array must not throw.
    @Test
    public void messagesWithNullElementDoesNotThrow()
    {
        String body = "{\"detail\":{\"messages\":[\"enter otp\",null]},\"result\":{\"status\":true,\"value\":false}}";
        PIResponse r = parser.parsePIResponse(body);
        assertNotNull(r);
        assertNull(r.error);
        assertEquals(1, r.messages.size());
        assertEquals("enter otp", r.messages.get(0));
    }

    // M3 — a body without a "result" key must not NPE.
    @Test
    public void rolloutInfoWithoutResultDoesNotThrow()
    {
        RolloutInfo ri = parser.parseRolloutInfo("{\"detail\":{\"serial\":\"OATH1\"}}");
        assertNotNull(ri);
    }

    // M4 — a non-JSON /auth body must return null, not throw.
    @Test
    public void getJwtNonJsonReturnsNull()
    {
        assertNull(parser.getJWT("<html>502 Bad Gateway</html>"));
    }

    // M5 — one token with a wrongly-typed "info" must not abort the whole list.
    @Test
    public void tokenListWithBadInfoStillParsesAllTokens()
    {
        String body = "{\"result\":{\"status\":true,\"value\":{\"count\":2,\"tokens\":[" +
                      "{\"serial\":\"A1\",\"tokentype\":\"hotp\",\"info\":\"not-an-object\"}," +
                      "{\"serial\":\"A2\",\"tokentype\":\"totp\",\"info\":{\"tokenkind\":\"software\"}}" +
                      "]}}}";
        List<TokenInfo> tokens = parser.parseTokenInfoList(body);
        assertNotNull(tokens);
        assertEquals(2, tokens.size());
        assertEquals("A1", tokens.get(0).serial);
        assertEquals("A2", tokens.get(1).serial);
    }

    // M7 — leaf accessors must tolerate the value arriving as a different JSON scalar type.
    @Test
    public void scalarTypeCoercion()
    {
        String body = "{\"result\":{\"status\":true,\"value\":{\"tokens\":[" +
                      "{\"serial\":12345,\"active\":\"true\",\"otplen\":\"6\",\"tokentype\":\"hotp\"}" +
                      "]}}}";
        List<TokenInfo> tokens = parser.parseTokenInfoList(body);
        assertNotNull(tokens);
        assertEquals(1, tokens.size());
        TokenInfo t = tokens.get(0);
        assertEquals("12345", t.serial);   // numeric serial stringified, not lost
        assertTrue(t.active);              // "true" string coerced to boolean
        assertEquals(6, t.otpLen);         // "6" string coerced to int
    }

    // L (capability CCE) — capabilities sent as a primitive must return null (unknown), not throw.
    @Test
    public void capabilitiesWrongTypeReturnsNull()
    {
        assertNull(parser.parseRememberDeviceCapability("{\"result\":{\"value\":{\"capabilities\":42}}}"));
    }

    // M1 — pollTransaction must return ChallengeStatus.none on a transport failure (null body), not NPE.
    @Test
    public void pollTransactionNoServerReturnsNone()
    {
        // No mock server running on :1080 -> runRequestAsync returns null.
        assertEquals(ChallengeStatus.none, privacyIDEA.pollTransaction("does-not-matter"));
    }
}
