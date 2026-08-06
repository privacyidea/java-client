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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Behaviour tests for {@link Endpoint}: request-parameter encoding (must be single, not double) and the
 * log-hygiene guarantees (secrets redacted, no log forging). Each corresponds to an audit finding.
 */
public class TestEndpointBehavior
{
    private ClientAndServer mockServer;
    private final List<String> logMessages = new ArrayList<>();

    /** Capturing logger so assertions can inspect exactly what the client would write to the IdP log. */
    private final IPILogger capturingLogger = new IPILogger()
    {
        @Override public void log(String message) {logMessages.add(message);}
        @Override public void error(String message) {logMessages.add(message);}
        @Override public void log(Throwable t) {logMessages.add(String.valueOf(t));}
        @Override public void error(Throwable t) {logMessages.add(String.valueOf(t));}
    };

    private PrivacyIDEA privacyIDEA;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(capturingLogger)
                                 .build();
    }

    private String allLogs()
    {
        return String.join("\n", logMessages);
    }

    private void respondOk()
    {
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check"))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 20));
    }

    // H5 — a value with reserved characters must be encoded exactly once, not twice.
    @Test
    public void parametersAreEncodedExactlyOnce()
    {
        respondOk();
        // '+' -> %2B, '&' -> %26 with a single form-encode. A double encode would produce %252B / %2526.
        privacyIDEA.validateCheck("testuser", "a+b&c");

        HttpRequest[] recorded = mockServer.retrieveRecordedRequests(HttpRequest.request().withPath("/validate/check"));
        assertTrue("expected a recorded request", recorded.length > 0);
        String body = recorded[0].getBodyAsString();
        assertTrue("single-encoded pass expected, was: " + body, body.contains("pass=a%2Bb%26c"));
        assertFalse("value must not be double-encoded: " + body, body.contains("%252B"));
        assertFalse("value must not be double-encoded: " + body, body.contains("%2526"));
    }

    // H1 — the Authorization header (bearer JWT) must never be logged in clear.
    @Test
    public void authorizationHeaderIsMasked()
    {
        respondOk();
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer super-secret-jwt-value");
        privacyIDEA.validateCheck("testuser", "123456", headers);

        assertFalse("JWT leaked to log: " + allLogs(), allLogs().contains("super-secret-jwt-value"));
        assertTrue(allLogs().contains("Authorization: <hidden>"));
    }

    // H2 / length-leak — secret params are redacted, and the mask does not disclose the secret's length.
    @Test
    public void secretParamsAreRedactedWithoutRevealingLength()
    {
        respondOk();
        privacyIDEA.validateCheck("testuser", "hunter2secret");

        assertFalse("OTP/pass leaked to log: " + allLogs(), allLogs().contains("hunter2secret"));
        assertTrue(allLogs().contains("pass=<hidden>"));
        // Old behaviour replaced the value with one '*' per char, disclosing the length.
        assertFalse("length disclosed via '*' mask", allLogs().contains("*************"));
    }

    // M10 — a value containing CR/LF must not forge extra log lines.
    @Test
    public void controlCharsInValueAreSanitizedInLog()
    {
        respondOk();
        privacyIDEA.validateCheck("evil\nINJECTED-LINE", "123456");

        assertFalse("raw newline reached the log (forgeable)", allLogs().contains("evil\nINJECTED-LINE"));
        assertTrue("newline should be replaced by a space", allLogs().contains("user=evil INJECTED-LINE"));
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
