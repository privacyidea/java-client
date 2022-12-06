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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;

public class TestWebAuthn
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "Test";
    private final String pass = "Test";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .logger(new PILogImplementation()).build();
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void testSuccess()
    {
        String webauthnSignResponse = "{" + "\"credentialid\":\"X9FrwMfmzj...saw21\"," +
                                      "\"authenticatordata\":\"xGzvgq0bVGR3WR0A...ZJdA7cBAAAACA\"," +
                                      "\"clientdata\":\"eyJjaGFsbG...dfhs\"," +
                                      "\"signaturedata\":\"MEUCIQDNrG...43hc\"}";

        String responseBody =
                "{\n" + "  \"detail\": {\n" + "    \"message\": \"matching 1 tokens\",\n" + "    \"otplen\": 6,\n" +
                "    \"serial\": \"PISP0001C673\",\n" + "    \"threadid\": 140536383567616,\n" +
                "    \"type\": \"totp\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" + "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" +
                "  \"time\": 1589276995.4397042,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" + "}";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_VALIDATE_CHECK).withMethod("POST").withBody(
                          "user=Test&transaction_id=16786665691788289392&pass=&credentialid=X9FrwMfmzj...saw21&clientdata=eyJjaGFsbG...dfhs&signaturedata=MEUCIQDNrG...43hc&authenticatordata=xGzvgq0bVGR3WR0A...ZJdA7cBAAAACA"))
                  .respond(HttpResponse.response().withBody(responseBody));

        PIResponse response = privacyIDEA.validateCheckWebAuthn("Test", "16786665691788289392", webauthnSignResponse,
                                                                "test.it");

        assertNotNull(response);
        assertEquals("matching 1 tokens", response.message);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertEquals(6, response.otpLength);
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testTriggerWebAuthn()
    {
        String webauthnrequest = "{\n" + "            \"allowCredentials\": [\n" + "              {\n" +
                                 "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                                 "                \"transports\": [\n" + "                  \"internal\",\n" +
                                 "                  \"nfc\",\n" + "                  \"ble\",\n" +
                                 "                  \"usb\"\n" + "                ],\n" +
                                 "                \"type\": \"public-key\"\n" + "              }\n" +
                                 "            ],\n" +
                                 "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                                 "            \"rpId\": \"office.netknights.it\",\n" +
                                 "            \"timeout\": 60000,\n" +
                                 "            \"userVerification\": \"preferred\"\n" + "          }\n";

        String responseBody =
                "{\n" + "  \"detail\": {\n" + "    \"preferred_client_mode\": \"webauthn\",\n" + "    \"attributes\": {\n" + "      \"hideResponseInput\": true,\n" +
                "      \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "      \"webAuthnSignRequest\": {\n" + "        \"allowCredentials\": [\n" + "          {\n" +
                "            \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "            \"transports\": [\n" + "              \"internal\",\n" + "              \"nfc\",\n" +
                "              \"ble\",\n" + "              \"usb\"\n" + "            ],\n" +
                "            \"type\": \"public-key\"\n" + "          }\n" + "        ],\n" +
                "        \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "        \"rpId\": \"office.netknights.it\",\n" + "        \"timeout\": 60000,\n" +
                "        \"userVerification\": \"preferred\"\n" + "      }\n" + "    },\n" +
                "    \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                "    \"messages\": [\n" +
                "      \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"\n" + "    ],\n" +
                "    \"multi_challenge\": [\n" + "      {\n" + "        \"attributes\": {\n" +
                "          \"hideResponseInput\": true,\n" +
                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "          \"webAuthnSignRequest\": " + webauthnrequest + "        },\n" +
                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                "        \"serial\": \"WAN00025CE7\",\n" + "        \"transaction_id\": \"16786665691788289392\",\n" +
                "        \"type\": \"webauthn\"\n" + "      }\n" + "    ],\n" + "    \"serial\": \"WAN00025CE7\",\n" +
                "    \"threadid\": 140040275289856,\n" + "    \"transaction_id\": \"16786665691788289392\",\n" +
                "    \"transaction_ids\": [\n" + "      \"16786665691788289392\"\n" + "    ],\n" +
                "    \"type\": \"webauthn\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" + "    \"authentication\": \"CHALLENGE\",\n" + "    \"status\": true,\n" +
                "    \"value\": false\n" + "  },\n" + "  \"time\": 1611916339.8448942\n" + "}\n" + "";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_VALIDATE_CHECK).withMethod("POST")
                                   .withBody("user=" + username + "&pass=" + pass)).respond(HttpResponse.response()
                                                                                                        // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                                                                                        .withBody(
                                                                                                                responseBody));

        PIResponse response = privacyIDEA.validateCheck(username, pass);

        Optional<Challenge> opt = response.multiChallenge().stream()
                                          .filter(challenge -> TOKEN_TYPE_WEBAUTHN.equals(challenge.getType()))
                                          .findFirst();
        assertTrue(opt.isPresent());
        assertEquals(AuthenticationStatus.CHALLENGE, response.authentication);
        assertEquals("webauthn", response.preferredClientMode);
        Challenge a = opt.get();
        if (a instanceof WebAuthn)
        {
            WebAuthn b = (WebAuthn) a;
            String trimmedRequest = webauthnrequest.replaceAll("\n", "").replaceAll(" ", "");
            assertEquals(trimmedRequest, b.signRequest());
        }
        else
        {
            fail();
        }
    }

    @Test
    public void testMergedSignRequest()
    {
        String expectedMergedResponse = "{" + "\"allowCredentials\":[{" +
                                        "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
                                        "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," +
                                        "\"type\":\"public-key\"}," + "{" +
                                        "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...wYxgitd4uoowT43EGm_x3mNhT1i-w\"," +
                                        "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," +
                                        "\"type\":\"public-key\"}]," +
                                        "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
                                        "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
                                        "\"userVerification\":\"preferred\"}";

        String respMultipleWebauthn =
                "{" + "\"detail\":{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," +
                "\"webAuthnSignRequest\":{" + "\"allowCredentials\":[{" +
                "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...KwYxgitd4uoowT43EGm_x3mNhT1i-w\"," +
                "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
                "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
                "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}}," +
                "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," +
                "\"messages\":[\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"]," +
                "\"multi_challenge\":[{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," +
                "\"webAuthnSignRequest\":{" + "\"allowCredentials\":[{" +
                "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
                "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
                "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
                "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}}," +
                "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\"," +
                "\"serial\":\"WAN0003ABB5\"," + "\"transaction_id\":\"00699705595414705468\"," +
                "\"type\":\"webauthn\"}," + "{\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," +
                "\"webAuthnSignRequest\":{" + "\"allowCredentials\":[{" +
                "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...wYxgitd4uoowT43EGm_x3mNhT1i-w\"," +
                "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
                "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
                "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}}," +
                "\"message\":\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," +
                "\"serial\":\"WAN00042278\"," + "\"transaction_id\":\"00699705595414705468\"," +
                "\"type\":\"webauthn\"}]," + "\"serial\":\"WAN00042278\"," + "\"threadid\":140050952959744," +
                "\"transaction_id\":\"00699705595414705468\"," +
                "\"transaction_ids\":[\"00699705595414705468\",\"00699705595414705468\"]," + "\"type\":\"webauthn\"}," +
                "\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," +
                "\"time\":1649754970.915023," + "\"version\":\"privacyIDEA 3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
                "\"signature\":\"rsa_sha256_pss:74fac28b3163d4ac3f76...9237bb6c32c0d03de39\"}";

        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(respMultipleWebauthn);
        String trimmedRequest = expectedMergedResponse.replaceAll("\n", "").replaceAll(" ", "");
        String merged1 = piResponse1.mergedSignRequest();

        assertEquals(trimmedRequest, merged1);

        // short test otpMessage()
        String otpMessage = piResponse1.otpMessage();

        assertEquals("Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), " +
                     "Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", otpMessage);
    }
}
