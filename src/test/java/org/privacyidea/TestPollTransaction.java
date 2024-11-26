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

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.jetbrains.annotations.NotNull;
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

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .simpleLogger(System.out::println)
                                 .build();
    }

    @Test
    public void testPushSynchronous() throws InterruptedException
    {
        // Set the initial "challenges triggered" response, pass is empty here
        // How the challenge is triggered depends on the configuration of the privacyIDEA server
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass="))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.pollGetChallenges())
                                       .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse initialResponse = privacyIDEA.validateCheck(username, null);

        // Check the triggered challenges - the other things are already tested in org.privacyidea.TestOTP
        List<Challenge> challenges = initialResponse.multiChallenge;

        Challenge hotpChallenge = challenges.stream()
                                            .filter(c -> c.getSerial().equals("OATH00020121"))
                                            .findFirst()
                                            .orElse(null);
        assertNotNull(hotpChallenge);
        assertEquals("Bitte geben Sie einen OTP-Wert ein: ", hotpChallenge.getMessage());
        assertEquals("02659936574063359702", hotpChallenge.getTransactionID());
        assertEquals("hotp", hotpChallenge.getType());
        assertEquals("", hotpChallenge.getImage());
        assertTrue(hotpChallenge.getAttributes().isEmpty());

        assertEquals("push", initialResponse.preferredClientMode);

        Challenge pushChallenge = challenges.stream()
                                            .filter(c -> c.getSerial().equals("PIPU0001F75E"))
                                            .findFirst()
                                            .orElse(null);
        assertNotNull(pushChallenge);
        assertEquals("Please confirm the authentication on your mobile device!", pushChallenge.getMessage());
        assertEquals("02659936574063359702", pushChallenge.getTransactionID());
        assertEquals("push", pushChallenge.getType());
        assertTrue(pushChallenge.getAttributes().isEmpty());

        String imagePush = "";
        for (Challenge c : challenges)
        {
            if ("push".equals(c.getType()))
            {
                if (!c.getImage().isEmpty())
                {
                    imagePush = c.getImage();
                }
            }
        }
        assertEquals("dataimage", imagePush);

        List<String> triggeredTypes = initialResponse.triggeredTokenTypes();
        assertTrue(triggeredTypes.contains("push"));
        assertTrue(triggeredTypes.contains("hotp"));

        assertEquals(2, initialResponse.messages.size());

        // Set the server up to respond to the polling requests twice with "pending"
        setPollTransactionResponse(ChallengeStatus.pending, 2);

        // Polling is controlled by the code using the java-client
        for (int i = 0; i < 2; i++)
        {
            assertEquals(privacyIDEA.pollTransaction(initialResponse.transactionID), ChallengeStatus.pending);
            Thread.sleep(500);
        }

        // Set the server to respond with "declined"
        setPollTransactionResponse(ChallengeStatus.declined, 1);
        assertEquals(privacyIDEA.pollTransaction(initialResponse.transactionID), ChallengeStatus.declined);

        // Set the server to respond with "accept"
        setPollTransactionResponse(ChallengeStatus.accept, 1);
        assertEquals(privacyIDEA.pollTransaction(initialResponse.transactionID), ChallengeStatus.accept);

        // Set the server to respond with "none" by not including or invalid challenge_status parameter
        setPollTransactionResponse(ChallengeStatus.none, 1);
        assertEquals(privacyIDEA.pollTransaction(initialResponse.transactionID), ChallengeStatus.none);

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

    private void setFinalizationResponse(String transactionID)
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("POST")
                                   .withPath("/validate/check")
                                   .withBody("user=" + username + "&pass=&transaction_id=" + transactionID))
                  .respond(HttpResponse.response()
                                       .withBody(Utils.foundMatchingChallenge()));
    }

    private void setPollTransactionResponse(ChallengeStatus challengeStatus, int times)
    {
        String challengeStatusParameter = getChallengeStatusParameter(challengeStatus);
        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withPath("/validate/polltransaction")
                                   .withQueryStringParameter("transaction_id", "02659936574063359702"), Times.exactly(times))
                  .respond(HttpResponse.response()
                                       .withBody("{\n\"id\": 1,\n\"jsonrpc\": \"2.0\",\n" + challengeStatusParameter +
                                                 "\"result\": {\n\"status\": true\n},\n\"time\": 1589446811.1909237,\n\"version\": \"privacyIDEA 3.2.1\",\n" +
                                                 "\"versionnumber\": \"3.2.1\",\n\"signature\": \"rsa_sha256_pss:\"\n}")
                                       .withDelay(TimeUnit.MILLISECONDS, 50));
    }

    private static @NotNull String getChallengeStatusParameter(ChallengeStatus challengeStatus)
    {
        String challengeStatusParameter = "";
        if (challengeStatus == ChallengeStatus.accept)
        {
            challengeStatusParameter = "\"detail\": {\n\"challenge_status\": \"accept\"\n},\n";
        }
        else if (challengeStatus == ChallengeStatus.declined)
        {
            challengeStatusParameter = "\"detail\": {\n\"challenge_status\": \"declined\"\n},\n";

        }
        else if (challengeStatus == ChallengeStatus.pending)
        {
            challengeStatusParameter = "\"detail\": {\n\"challenge_status\": \"pending\"\n},\n";
        }
        return challengeStatusParameter;
    }
    
    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
