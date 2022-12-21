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

import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TestPollTransaction
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "testuser";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .logger(new PILogImplementation()).simpleLogger(System.out::println).build();
    }

    @Test
    public void testPushSynchronous() throws InterruptedException
    {
        // Set the initial "challenges triggered" response, pass is empty here
        // How the challenge is triggered depends on the configuration of the privacyIDEA server
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=")).respond(
                HttpResponse.response().withContentType(MediaType.APPLICATION_JSON).withBody(
                                    "{\n" + "  \"detail\": {\n" + "    \"preferred_client_mode\": \"poll\",\n" + "    \"attributes\": null,\n" +
                                    "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
                                    "    \"messages\": [\n" + "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                    "      \"Please confirm the authentication on your mobile device!\"\n" + "    ],\n" +
                                    "    \"multi_challenge\": [\n" + "      {\n" + "        \"attributes\": null,\n" +
                                    "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                    "        \"serial\": \"OATH00020121\",\n" +
                                    "        \"transaction_id\": \"02659936574063359702\",\n" + "        \"type\": \"hotp\"\n" +
                                    "      },\n" + "      {\n" + "        \"attributes\": null,\n" +
                                    "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
                                    "        \"serial\": \"PIPU0001F75E\",\n" +
                                    "        \"transaction_id\": \"02659936574063359702\",\n" + "        \"type\": \"push\"\n" +
                                    "      }\n" + "    ],\n" + "    \"serial\": \"PIPU0001F75E\",\n" +
                                    "    \"threadid\": 140040525666048,\n" + "    \"transaction_id\": \"02659936574063359702\",\n" +
                                    "    \"transaction_ids\": [\n" + "      \"02659936574063359702\",\n" +
                                    "      \"02659936574063359702\"\n" + "    ],\n" + "    \"type\": \"push\"\n" + "  },\n" +
                                    "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" + "  \"result\": {\n" +
                                    "    \"status\": true,\n" + "    \"value\": false\n" + "  },\n" +
                                    "  \"time\": 1589360175.594304,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                                    "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" + "}")
                            .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse initialResponse = privacyIDEA.validateCheck(username, null);

        // Check the triggered challenges - the other things are already tested in org.privacyidea.TestOTP
        List<Challenge> challenges = initialResponse.multiChallenge();

        Challenge hotpChallenge = challenges.stream().filter(c -> c.getSerial().equals("OATH00020121")).findFirst()
                                            .orElse(null);
        assertNotNull(hotpChallenge);
        assertEquals("Bitte geben Sie einen OTP-Wert ein: ", hotpChallenge.getMessage());
        assertEquals("02659936574063359702", hotpChallenge.getTransactionID());
        assertEquals("hotp", hotpChallenge.getType());
        assertEquals("", hotpChallenge.getImage());
        assertTrue(hotpChallenge.getAttributes().isEmpty());

        assertEquals("push", initialResponse.preferredClientMode);

        Challenge pushChallenge = challenges.stream().filter(c -> c.getSerial().equals("PIPU0001F75E")).findFirst()
                                            .orElse(null);
        assertNotNull(pushChallenge);
        assertEquals("Please confirm the authentication on your mobile device!", pushChallenge.getMessage());
        assertEquals("02659936574063359702", pushChallenge.getTransactionID());
        assertEquals("push", pushChallenge.getType());
        assertTrue(pushChallenge.getAttributes().isEmpty());

        List<String> triggeredTypes = initialResponse.triggeredTokenTypes();
        assertTrue(triggeredTypes.contains("push"));
        assertTrue(triggeredTypes.contains("hotp"));

        assertEquals(2, initialResponse.messages.size());

        // Set the server up to respond to the polling requests twice with false
        setPollTransactionResponse(false, 2);

        // Polling is controlled by the code using the sdk
        for (int i = 0; i < 2; i++)
        {
            assertFalse(privacyIDEA.pollTransaction(initialResponse.transactionID));
            Thread.sleep(500);
        }

        // Set the server to respond with true
        setPollTransactionResponse(true, 1);
        assertTrue(privacyIDEA.pollTransaction(initialResponse.transactionID));

        // Now the transaction has to be finalized manually
        setFinalizationResponse(initialResponse.transactionID);

        PIResponse response = privacyIDEA.validateCheck(username, null, initialResponse.transactionID);
        assertTrue(response.value);

        //push side functions
        boolean pushAvailable = response.pushAvailable();
        assertFalse(pushAvailable);
        String pushMessage = response.pushMessage();
        assertEquals("", pushMessage);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }

    private void setFinalizationResponse(String transactionID)
    {
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=&transaction_id=" + transactionID)).respond(
                HttpResponse.response().withBody(
                        "{\n" + "    \"detail\": {\n" + "        \"message\": \"Found matching challenge\",\n" +
                        "        \"serial\": \"PIPU0001F75E\",\n" + "        \"threadid\": 140586038396672\n" +
                        "    },\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" + "    \"result\": {\n" +
                        "        \"status\": true,\n" + "        \"value\": true\n" + "    },\n" +
                        "    \"time\": 1589446811.2747126,\n" + "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                        "    \"versionnumber\": \"3.2.1\",\n" + "    \"signature\": \"rsa_sha256_pss:\"\n" + "}"));
    }

    private void setPollTransactionResponse(boolean value, int times)
    {
        String val = value ? "true" : "false";
        mockServer.when(HttpRequest.request().withMethod("GET").withPath("/validate/polltransaction")
                                   .withQueryStringParameter("transaction_id", "02659936574063359702"),
                        Times.exactly(times)).respond(HttpResponse.response().withBody(
                                                                          "{\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" + "    \"result\": {\n" +
                                                                          "        \"status\": true,\n" + "        \"value\": " + val + "\n" + "    },\n" +
                                                                          "    \"time\": 1589446811.1909237,\n" + "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                                                          "    \"versionnumber\": \"3.2.1\",\n" + "    \"signature\": \"rsa_sha256_pss:\"\n" + "}")
                                                                  .withDelay(TimeUnit.MILLISECONDS, 50));
    }
}
