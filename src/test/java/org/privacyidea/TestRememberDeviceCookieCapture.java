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

import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Regression: the remember-device {@code Set-Cookie} the server issues on a successful auth must be surfaced
 * on {@link PIResponse#setCookieHeaders} for ALL auth paths, not only the plain OTP {@code validateCheck}.
 * WebAuthn and passkey previously used a body-only request helper and dropped the cookie, so "remember this
 * device" silently did nothing when the user authenticated with a security key / passkey.
 */
public class TestRememberDeviceCookieCapture
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private static final String COOKIE = "pi_remember_device=1:abcdef; Path=/; Max-Age=604800";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check"))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withHeader("Set-Cookie", COOKIE)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 20));

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void webauthnSurfacesSetCookie()
    {
        PIResponse r = privacyIDEA.validateCheckWebAuthn("testuser", "txn-1", "{}", "https://origin");
        assertNotNull(r);
        assertNotNull("setCookieHeaders must be populated on the WebAuthn path", r.setCookieHeaders);
        assertTrue(r.setCookieHeaders.stream().anyMatch(c -> c.contains("pi_remember_device")));
    }

    @Test
    public void passkeySurfacesSetCookie()
    {
        PIResponse r = privacyIDEA.validateCheckPasskey("txn-2", "{}", "https://origin", Collections.emptyMap());
        assertNotNull(r);
        assertNotNull("setCookieHeaders must be populated on the passkey path", r.setCookieHeaders);
        assertTrue(r.setCookieHeaders.stream().anyMatch(c -> c.contains("pi_remember_device")));
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
