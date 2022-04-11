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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class TestTriggerChallenge
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    String serviceAccount = "service";
    String servicePass = "pass";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass).logger(new PILogImplementation())
                                 .realm("realm").build();
    }

    @Test
    public void testTriggerChallengeSuccess()
    {
        String response = "{\"detail\":{" + "\"attributes\":null," + "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
                          "\"messages\":[\"BittegebenSieeinenOTP-Wertein:\"]," + "\"multi_challenge\":[{" +
                          "\"attributes\":null," + "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
                          "\"serial\":\"TOTP00021198\"," + "\"transaction_id\":\"16734787285577957577\"," +
                          "\"type\":\"totp\"}]," + "\"serial\":\"TOTP00021198\"," + "\"threadid\":140050885818112," +
                          "\"transaction_id\":\"16734787285577957577\"," +
                          "\"transaction_ids\":[\"16734787285577957577\"]," + "\"type\":\"totp\"}," + "\"id\":1," +
                          "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," +
                          "\"time\":1649666174.5351279," + "\"version\":\"privacyIDEA3.6.3\"," +
                          "\"versionnumber\":\"3.6.3\"," +
                          "\"signature\":\"rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b\"}";

        String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody("{\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
                                                 "    \"result\": {\n" + "        \"status\": true,\n" +
                                                 "        \"value\": {\n" + "            \"log_level\": 20,\n" +
                                                 "            \"menus\": [\n" + "                \"components\",\n" +
                                                 "                \"machines\"\n" + "            ],\n" +
                                                 "            \"realm\": \"\",\n" + "            \"rights\": [\n" +
                                                 "                \"policydelete\",\n" +
                                                 "                \"resync\"\n" + "            ],\n" +
                                                 "            \"role\": \"admin\",\n" + "            \"token\": \"" +
                                                 authToken + "\",\n" + "            \"username\": \"admin\",\n" +
                                                 "            \"logout_time\": 120,\n" +
                                                 "            \"default_tokentype\": \"hotp\",\n" +
                                                 "            \"user_details\": false,\n" +
                                                 "            \"subscription_status\": 0\n" + "        }\n" +
                                                 "    },\n" + "    \"time\": 1589446794.8502703,\n" +
                                                 "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                                 "    \"versionnumber\": \"3.2.1\",\n" +
                                                 "    \"signature\": \"rsa_sha256_pss:\"\n" + "}"));

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_TRIGGERCHALLENGE).withMethod("POST")
                                   .withBody("user=testuser&realm=realm"))
                  .respond(HttpResponse.response().withBody(response));

        String username = "testuser";
        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges(username);

        assertEquals(1, responseTriggerChallenge.id);
        assertEquals("BittegebenSieeinenOTP-Wertein:", responseTriggerChallenge.message);
        assertEquals("2.0", responseTriggerChallenge.jsonRPCVersion);
        assertEquals("3.6.3", responseTriggerChallenge.piVersion);
        assertEquals("rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b", responseTriggerChallenge.signature);
        // Trim all whitespaces, newlines
        assertEquals(response.replaceAll("[\n\r]", ""), responseTriggerChallenge.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(response.replaceAll("[\n\r]", ""), responseTriggerChallenge.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(responseTriggerChallenge.status);
        assertFalse(responseTriggerChallenge.value);
    }

    @Test
    public void testNoServiceAccount()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .logger(new PILogImplementation()).build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testWrongServerURL()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://12ds7:1nvcbn080", "test").sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass).logger(new PILogImplementation())
                                 .realm("realm").build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testNoUsername()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .serviceAccount(serviceAccount, servicePass).logger(new PILogImplementation())
                                 .realm("realm").build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("");

        assertNull(responseTriggerChallenge);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}