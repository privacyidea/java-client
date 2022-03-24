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
import org.junit.After;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

    @After
    public void teardown() {
        mockServer.stop();
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

    @Test
    public void testMergedSignRequest() {
        String expectedMergedResponse = "{\n" + "   \"allowCredentials\":[\n" + "      {\n" +
                                        "         \"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1rvpnvbfe7TWPAz5U8R7I_R-SagNpYYD5emHTeLJ_8jRm5xVNqWT3f9-CfMDuTKk2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\",\n" +
                                        "         \"transports\":[\n" + "            \"ble\",\n" +
                                        "            \"usb\",\n" + "            \"internal\",\n" +
                                        "            \"nfc\"\n" + "         ],\n" +
                                        "         \"type\":\"public-key\"\n" + "      },\n" + "      {\n" +
                                        "         \"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0-e4bkf8IVaqzjO4lkVjwNyLmOx9tHwO-BKwYxgitd4uoowT43EGm_x3mNhT1i-w\",\n" +
                                        "         \"transports\":[\n" + "            \"ble\",\n" +
                                        "            \"usb\",\n" + "            \"internal\",\n" +
                                        "            \"nfc\"\n" + "         ],\n" +
                                        "         \"type\":\"public-key\"\n" + "      }\n" + "   ],\n" +
                                        "   \"challenge\":\"4h0W-GXDhDK63aNKHBBPhDtV9812l0BQI06mYSYcDTQ\",\n" +
                                        "   \"rpId\":\"office.netknights.it\",\n" + "   \"timeout\":60000,\n" +
                                        "   \"userVerification\":\"preferred\"\n" + "}";

        String emptyPIResp = "";

        String respMultipleWebauthn = "{\n" + "   \"detail\":{\n" + "      \"attributes\":{\n" +
                                      "         \"hideResponseInput\":true,\n" +
                                      "         \"img\":\"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                      "         \"webAuthnSignRequest\":{\n" + "            \"allowCredentials\":[\n" +
                                      "               {\n" +
                                      "                  \"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0-e4bkf8IVaqzjO4lkVjwNyLmOx9tHwO-BKwYxgitd4uoowT43EGm_x3mNhT1i-w\",\n" +
                                      "                  \"transports\":[\n" + "                     \"ble\",\n" +
                                      "                     \"usb\",\n" + "                     \"internal\",\n" +
                                      "                     \"nfc\"\n" + "                  ],\n" +
                                      "                  \"type\":\"public-key\"\n" + "               }\n" +
                                      "            ],\n" +
                                      "            \"challenge\":\"4h0W-GXDhDK63aNKHBBPhDtV9812l0BQI06mYSYcDTQ\",\n" +
                                      "            \"rpId\":\"office.netknights.it\",\n" +
                                      "            \"timeout\":60000,\n" +
                                      "            \"userVerification\":\"preferred\"\n" + "         }\n" +
                                      "      },\n" +
                                      "      \"message\":\"Bitte geben Sie einen OTP-Wert ein: , Bitte geben Sie einen OTP-Wert ein: , Bitte scannen Sie den QR-Code, Bitte best\\u00e4tigen Sie mit Ihrem U2F token (Yubico U2F EE Serial 61730834), Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                      "      \"messages\":[\n" +
                                      "         \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                      "         \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                      "         \"Bitte scannen Sie den QR-Code\",\n" +
                                      "         \"Bitte best\\u00e4tigen Sie mit Ihrem U2F token (Yubico U2F EE Serial 61730834)\",\n" +
                                      "         \"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\n" +
                                      "         \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"\n" +
                                      "      ],\n" + "      \"multi_challenge\":[\n" + "         {\n" +
                                      "            \"attributes\":null,\n" +
                                      "            \"message\":\"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                      "            \"serial\":\"TOTP0001AFB9\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"totp\"\n" + "         },\n" + "         {\n" +
                                      "            \"attributes\":null,\n" +
                                      "            \"message\":\"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                      "            \"serial\":\"TOTP00021198\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"totp\"\n" + "         },\n" + "         {\n" +
                                      "            \"attributes\":{\n" +
                                      "               \"hideResponseInput\":true,\n" +
                                      "               \"img\":\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAcIAAAHCAQAAAABUY/ToAAADiklEQVR4nO2cUWrrOhCGv7k29FGGLiBLkXdwl1SypLMDeyndgfUYcPjvgyTLSXPgcGhI0jvz4CapP2zBIM38M5KJv7P5n78EwUknnXTSSSeddPL5SCvWA5yt/taXy5jMINW7xge/rZNPSUZJ0gLMQyfmAaTlbNICOh4kG+kkSbokH/G2Tj4V2Ze/aYD4CwwMkfoVwtobYMRPQyQw6NYHvq2TL0HGpZN96GRmA0haATrZeL9nOvnDyLBS1rLPHhsBHYc7P9PJVybrWhYEJID0vkJ6k8Vf3WrQyaJKnL0XJF9rnE7enZzN8uKVLS7bDakH0puAc07LvuuZTv4QEl0ahJp5tVztxn2aXmucTt6PzL5RJ54uO42m+gnoBGGlfXUfcvIGqeMAkk5mdpAgnMzGILW8jHnopKkqkK85TifvQdY1aunUvhKXqifGpZMmOhG1lkAp+jzk5N6Kq2hFU1iLIBSb+4TiOTuJ2n3IyQur8xDkySi2qDm0eQiPh5z8rbVsTFIJnTVt/85T0OZceVpyH3LyFnkudft56IpLTWFL9cOpRNI74ehFx+nkt5O7IDr7S9ziIaDESBMtsHZ9yMnfkOFkmlKPjvamrE5nR0o9EFbsQycrXx/+tk4+E7npzyslKFogp2k5388BUA2UXKd28qvtcjDo8qedI01Nor7I/N2HnLwm8+K1Qvzsya1DE2BjvpR4yEY672N08jaZ4yEzs0OZfVoTEfNAdi5IXrd38tqqTt1qY1DlRYo+NIUmZXs85OSVbf3U7yvz2MkAjHDuRepWIwiLy7mH9C5yo/XD3tbJpyfDep3RlzbY1MN8OBlRJ98b5OSVtZprsVBKGtJWvM/3LXvC1zInr8n0VrQgkllOzsYWWC9gNnTyWoeTN6zWOsjbgsol1/K3Gn2tnHnN1ckb1vKytqDtcrXWP1TER+/9cPLaWjy0k6OLbF3bPppF16md/GK6tF3La7agXcm+9hm5Dzl5TbZzP3Kfx/Gw6YkL1GC7h7h4T76Tt8kSRJcCWd2ZuO1brHLRtz7TyR9Gpnqu0DycrTYMtQr+yZjNvH/IyT8l7WMBHa34i43UHuv54OcPOXltX/Sh2jW0U6xbzXXXnf9a43TyfuT1uR+ah0UWP3sE516kHstnWAHM/25B0WuN08n7kfu9h21v/aYs1o2KW4s+uD7k5KWZn3HupJNOOumkk07+z8n/AFOMPZbzTEiQAAAAAElFTkSuQmCC\",\n" +
                                      "               \"poll\":true,\n" +
                                      "               \"value\":\"tiqrauth://lukas_ucs5@org.privacyidea/11083173066293349938/c0c89b5345/privacyIDEA\"\n" +
                                      "            },\n" +
                                      "            \"message\":\"Bitte scannen Sie den QR-Code\",\n" +
                                      "            \"next_pin_change\":\"2022-01-11T13:32+0100\",\n" +
                                      "            \"pin_change\":true,\n" +
                                      "            \"serial\":\"TiQR000151DA\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"tiqr\"\n" + "         },\n" + "         {\n" +
                                      "            \"attributes\":{\n" +
                                      "               \"hideResponseInput\":true,\n" +
                                      "               \"img\":\"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                      "               \"u2fSignRequest\":{\n" +
                                      "                  \"appId\":\"https://pi01.office.netknights.it/ttype/u2f\",\n" +
                                      "                  \"challenge\":\"1xtDYB97P2Vb9YmogMcTsRM1oDVWFGOpMOxEr0cxJdk\",\n" +
                                      "                  \"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQJYu4G5qB9l7ScjRRxA-M35cTH-uHWyMEpxs4WBzbkjlZqzZW1lC-jDdFd2pKDUsNnA\",\n" +
                                      "                  \"version\":\"U2F_V2\"\n" + "               }\n" +
                                      "            },\n" +
                                      "            \"message\":\"Bitte best\\u00e4tigen Sie mit Ihrem U2F token (Yubico U2F EE Serial 61730834)\",\n" +
                                      "            \"serial\":\"U2F00014651\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"u2f\"\n" + "         },\n" + "         {\n" +
                                      "            \"attributes\":{\n" +
                                      "               \"hideResponseInput\":true,\n" +
                                      "               \"img\":\"\",\n" + "               \"webAuthnSignRequest\":{\n" +
                                      "                  \"allowCredentials\":[\n" + "                     {\n" +
                                      "                        \"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1rvpnvbfe7TWPAz5U8R7I_R-SagNpYYD5emHTeLJ_8jRm5xVNqWT3f9-CfMDuTKk2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\",\n" +
                                      "                        \"transports\":[\n" +
                                      "                           \"ble\",\n" +
                                      "                           \"usb\",\n" +
                                      "                           \"internal\",\n" +
                                      "                           \"nfc\"\n" + "                        ],\n" +
                                      "                        \"type\":\"public-key\"\n" + "                     }\n" +
                                      "                  ],\n" +
                                      "                  \"challenge\":\"4h0W-GXDhDK63aNKHBBPhDtV9812l0BQI06mYSYcDTQ\",\n" +
                                      "                  \"rpId\":\"office.netknights.it\",\n" +
                                      "                  \"timeout\":60000,\n" +
                                      "                  \"userVerification\":\"preferred\"\n" + "               }\n" +
                                      "            },\n" +
                                      "            \"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\n" +
                                      "            \"serial\":\"WAN0003ABB5\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"webauthn\"\n" + "         },\n" + "         {\n" +
                                      "            \"attributes\":{\n" +
                                      "               \"hideResponseInput\":true,\n" +
                                      "               \"img\":\"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                      "               \"webAuthnSignRequest\":{\n" +
                                      "                  \"allowCredentials\":[\n" + "                     {\n" +
                                      "                        \"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0-e4bkf8IVaqzjO4lkVjwNyLmOx9tHwO-BKwYxgitd4uoowT43EGm_x3mNhT1i-w\",\n" +
                                      "                        \"transports\":[\n" +
                                      "                           \"ble\",\n" +
                                      "                           \"usb\",\n" +
                                      "                           \"internal\",\n" +
                                      "                           \"nfc\"\n" + "                        ],\n" +
                                      "                        \"type\":\"public-key\"\n" + "                     }\n" +
                                      "                  ],\n" +
                                      "                  \"challenge\":\"4h0W-GXDhDK63aNKHBBPhDtV9812l0BQI06mYSYcDTQ\",\n" +
                                      "                  \"rpId\":\"office.netknights.it\",\n" +
                                      "                  \"timeout\":60000,\n" +
                                      "                  \"userVerification\":\"preferred\"\n" + "               }\n" +
                                      "            },\n" +
                                      "            \"message\":\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                      "            \"serial\":\"WAN00042278\",\n" +
                                      "            \"transaction_id\":\"11083173066293349938\",\n" +
                                      "            \"type\":\"webauthn\"\n" + "         }\n" + "      ],\n" +
                                      "      \"next_pin_change\":\"2022-01-11T13:32+0100\",\n" +
                                      "      \"pin_change\":true,\n" + "      \"serial\":\"WAN00042278\",\n" +
                                      "      \"threadid\":139831048673024,\n" +
                                      "      \"transaction_id\":\"11083173066293349938\",\n" +
                                      "      \"transaction_ids\":[\n" + "         \"11083173066293349938\",\n" +
                                      "         \"11083173066293349938\",\n" + "         \"11083173066293349938\",\n" +
                                      "         \"11083173066293349938\",\n" + "         \"11083173066293349938\",\n" +
                                      "         \"11083173066293349938\"\n" + "      ],\n" +
                                      "      \"type\":\"webauthn\"\n" + "   },\n" + "   \"id\":1,\n" +
                                      "   \"jsonrpc\":\"2.0\",\n" + "   \"result\":{\n" + "      \"status\":true,\n" +
                                      "      \"value\":false\n" + "   },\n" + "   \"time\":1647352314.1103587,\n" +
                                      "   \"version\":\"privacyIDEA 3.6.3\",\n" + "   \"versionnumber\":\"3.6.3\",\n" +
                                      "   \"signature\":\"rsa_sha256_pss:c10d64acedf2e3...1ffc15c8fbdd27450358bf12d4b\"\n" +
                                      "}";

        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(respMultipleWebauthn);
        String trimmedRequest = expectedMergedResponse.replaceAll("\n", "").replaceAll(" ", "");
        String merged1 = piResponse1.mergedSignRequest();

        assertEquals(trimmedRequest, merged1);
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
