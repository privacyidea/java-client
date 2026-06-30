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

import java.io.IOException;
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

import static org.junit.Assert.assertEquals;

/**
 * Verifies the User-Agent handling: the configured default is sent normally, but a User-Agent supplied in the
 * per-request headers overrides it (and is the only User-Agent sent). This is what lets a caller mark a single
 * request as originating from a specific flow (e.g. EntraID) without changing the shared client instance.
 */
public class TestUserAgent
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String defaultUserAgent = "default-ua/1.0";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check"))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 20));
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", defaultUserAgent)
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @After
    public void tearDown() throws IOException
    {
        privacyIDEA.close();
        mockServer.stop();
    }

    @Test
    public void testDefaultUserAgentUsedWhenNoOverride()
    {
        privacyIDEA.validateCheck("testuser", "123456");

        List<String> sent = recordedUserAgents();
        assertEquals(1, sent.size());
        assertEquals(defaultUserAgent, sent.get(0));
    }

    @Test
    public void testCallerUserAgentOverridesDefault()
    {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "entraid-via-keycloak/9.9");

        privacyIDEA.validateCheck("testuser", "123456", headers);

        List<String> sent = recordedUserAgents();
        // Exactly one User-Agent header, and it is the caller's value (not the configured default).
        assertEquals(1, sent.size());
        assertEquals("entraid-via-keycloak/9.9", sent.get(0));
    }

    /** The User-Agent header values on the single recorded /validate/check request. */
    private List<String> recordedUserAgents()
    {
        HttpRequest[] recorded = mockServer.retrieveRecordedRequests(HttpRequest.request().withPath("/validate/check"));
        assertEquals(1, recorded.length);
        return recorded[0].getHeader("User-Agent");
    }
}
