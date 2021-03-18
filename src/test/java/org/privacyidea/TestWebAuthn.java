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

import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;

public class TestWebAuthn implements IPILogger {
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;


    @Before
    public void setup() {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                .sslVerify(false)
                .logger(this)
                .build();
    }

    @Test
    public void test() {
        String username = "Test";
        String pass = username;

        String webauthnrequest = "{\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";
        mockServer.when(
                HttpRequest.request()
                        .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                        .withMethod("POST")
                        .withBody("user=" + username + "&pass=" + pass))
                .respond(HttpResponse.response()
                        // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                        .withBody("{\n" +
                                "  \"detail\": {\n" +
                                "    \"attributes\": {\n" +
                                "      \"hideResponseInput\": true,\n" +
                                "      \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "      \"webAuthnSignRequest\": {\n" +
                                "        \"allowCredentials\": [\n" +
                                "          {\n" +
                                "            \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                                "            \"transports\": [\n" +
                                "              \"internal\",\n" +
                                "              \"nfc\",\n" +
                                "              \"ble\",\n" +
                                "              \"usb\"\n" +
                                "            ],\n" +
                                "            \"type\": \"public-key\"\n" +
                                "          }\n" +
                                "        ],\n" +
                                "        \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                                "        \"rpId\": \"office.netknights.it\",\n" +
                                "        \"timeout\": 60000,\n" +
                                "        \"userVerification\": \"preferred\"\n" +
                                "      }\n" +
                                "    },\n" +
                                "    \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                "    \"messages\": [\n" +
                                "      \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"\n" +
                                "    ],\n" +
                                "    \"multi_challenge\": [\n" +
                                "      {\n" +
                                "        \"attributes\": {\n" +
                                "          \"hideResponseInput\": true,\n" +
                                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "          \"webAuthnSignRequest\": " + webauthnrequest +
                                "        },\n" +
                                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                "        \"serial\": \"WAN00025CE7\",\n" +
                                "        \"transaction_id\": \"16786665691788289392\",\n" +
                                "        \"type\": \"webauthn\"\n" +
                                "      }\n" +
                                "    ],\n" +
                                "    \"serial\": \"WAN00025CE7\",\n" +
                                "    \"threadid\": 140040275289856,\n" +
                                "    \"transaction_id\": \"16786665691788289392\",\n" +
                                "    \"transaction_ids\": [\n" +
                                "      \"16786665691788289392\"\n" +
                                "    ],\n" +
                                "    \"type\": \"webauthn\"\n" +
                                "  },\n" +
                                "  \"id\": 1,\n" +
                                "  \"jsonrpc\": \"2.0\",\n" +
                                "  \"result\": {\n" +
                                "    \"status\": true,\n" +
                                "    \"value\": false\n" +
                                "  },\n" +
                                "  \"time\": 1611916339.8448942\n" +
                                "}\n" +
                                ""));
        PIResponse response = privacyIDEA.validateCheck(username, pass);

        Optional<Challenge> opt = response.multiChallenge().stream().filter(challenge -> TOKEN_TYPE_WEBAUTHN.equals(challenge.getType())).findFirst();
        assertTrue(opt.isPresent());
        Challenge a = opt.get();
        if (a instanceof WebAuthn) {
            WebAuthn b = (WebAuthn) a;
            String trimmedRequest = webauthnrequest.replaceAll("\n", "").replaceAll(" ", "");
            assertEquals(trimmedRequest, b.signRequest());
        } else {
            fail();
        }
    }

    @Override
    public void log(String message) {
        System.out.println(message);
    }

    @Override
    public void error(String message) {
        System.err.println(message);
    }

    @Override
    public void log(Throwable t) {
        System.out.println(t.getMessage());
    }

    @Override
    public void error(Throwable t) {
        System.err.println(t.getMessage());
    }
}
