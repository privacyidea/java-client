/*
 * Copyright 2021 NetKnights GmbH - nils.behlen@netknights.it
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import java.util.concurrent.TimeUnit;
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

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .logger(new PILogImplementation()).build();
    }

    @Test
    public void testOTPSuccess()
    {
        String responseBody =
                "{\n" + "  \"detail\": {\n" + "    \"message\": \"matching 1 tokens\",\n" + "    \"otplen\": 6,\n" +
                "    \"serial\": \"PISP0001C673\",\n" + "    \"threadid\": 140536383567616,\n" +
                "    \"type\": \"totp\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" + "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" +
                "  \"time\": 1589276995.4397042,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" + "}";

        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp)).respond(
                HttpResponse.response().withContentType(MediaType.APPLICATION_JSON).withBody(responseBody)
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
        assertEquals(responseBody.replaceAll("[\n\r]", ""), response.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(responseBody.replaceAll("[\n\r]", ""), response.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testEmptyResponse()
    {
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=" + otp)).respond(
                HttpResponse.response().withContentType(MediaType.APPLICATION_JSON).withBody("")
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
        String responseBody =
                "{" + "\"detail\":null," + "\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"error\":{" +
                "\"code\":904," + "\"message\":\"ERR904: The user can not be found in any resolver in this realm!\"}," +
                "\"status\":false}," + "\"time\":1649752303.65651," + "\"version\":\"privacyIDEA 3.6.3\"," +
                "\"signature\":\"rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0\"}";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_VALIDATE_CHECK).withMethod("POST")
                                   .withBody("user=TOTP0001AFB9&pass=12"))
                  .respond(HttpResponse.response().withStatusCode(400).withBody(responseBody));

        String user = "TOTP0001AFB9";
        String pin = "12";

        PIResponse response = privacyIDEA.validateCheck(user, pin);

        assertEquals(responseBody, response.toString());
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertFalse(response.status);
        assertNotNull(response.error);
        assertEquals("rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0", response.signature);
    }
}