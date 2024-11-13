/*
 * Copyright 2023 NetKnights GmbH - nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
 * - Modified
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License here:
 * <a href="http://www.apache.org/licenses/LICENSE-2.0">License</a>
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import java.util.HashMap;
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestValidateCheck
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "testuser";
    private final String otp = "123456";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void testOTPSuccess()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse response = privacyIDEA.validateCheck(username, otp);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testOTPAddHeader()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        Map<String, String> header = new HashMap<>();
        header.put("accept-language", "en");
        PIResponse response = privacyIDEA.validateCheck(username, otp, header);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.matchingOneToken().replaceAll("[\n\r]", ""), response.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testLostValues()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.lostValues())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse response = privacyIDEA.validateCheck(username, otp);

        assertEquals("", response.piVersion);
        assertEquals("", response.message);
        assertEquals(0, response.otpLength);
        assertEquals(0, response.id);
        assertEquals("", response.jsonRPCVersion);
        assertEquals("", response.serial);
        assertEquals("", response.type);
        assertEquals("", response.signature);
    }

    @Test
    public void testEmptyResponse()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody("")
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse response = privacyIDEA.validateCheck(username, otp);

        // An empty response returns null
        assertNull(response);
    }

    @Test
    public void testNoResponse()
    {
        // No server setup - server might be offline/unreachable etc
        PIResponse response = privacyIDEA.validateCheck(username, otp);

        // No response also returns null - the exception is forwarded to the ILoggerBridge if set
        assertNull(response);
    }

    @Test
    public void testUserNotFound()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=TOTP0001AFB9&pass=12"))
                  .respond(HttpResponse.response().withStatusCode(400).withBody(Utils.errorUserNotFound()));

        String user = "TOTP0001AFB9";
        String pin = "12";

        PIResponse response = privacyIDEA.validateCheck(user, pin);

        assertEquals(Utils.errorUserNotFound(), response.toString());
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertFalse(response.status);
        assertNotNull(response.error);
        assertEquals("rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0", response.signature);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}