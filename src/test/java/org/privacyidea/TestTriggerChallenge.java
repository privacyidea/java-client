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
    String forwardClientIP = "127.0.0.1";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .forwardClientIP(forwardClientIP)
                                 .logger(new PILogImplementation())
                                 .realm("realm")
                                 .build();
    }

    @Test
    public void testTriggerChallengeSuccess()
    {
        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_TRIGGERCHALLENGE)
                                   .withMethod("POST")
                                   .withBody("user=testuser&realm=realm&client=127.0.0.1"))
                  .respond(HttpResponse.response().withBody(Utils.triggerChallengeSuccess()));

        String username = "testuser";
        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges(username);

        assertEquals("otp", responseTriggerChallenge.preferredClientMode);
        assertEquals(1, responseTriggerChallenge.id);
        assertEquals("BittegebenSieeinenOTP-Wertein:", responseTriggerChallenge.message);
        assertEquals("2.0", responseTriggerChallenge.jsonRPCVersion);
        assertEquals("3.6.3", responseTriggerChallenge.piVersion);
        assertEquals("rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b", responseTriggerChallenge.signature);
        // Trim all whitespaces, newlines
        assertEquals(Utils.triggerChallengeSuccess().replaceAll("[\n\r]", ""), responseTriggerChallenge.rawMessage.replaceAll("[\n\r]", ""));
        assertEquals(Utils.triggerChallengeSuccess().replaceAll("[\n\r]", ""), responseTriggerChallenge.toString().replaceAll("[\n\r]", ""));
        // result
        assertTrue(responseTriggerChallenge.status);
        assertFalse(responseTriggerChallenge.value);

        List<Challenge> challenges = responseTriggerChallenge.multiChallenge;
        String imageTOTP = "";
        for (Challenge c : challenges)
        {
            if ("totp".equals(c.getType()))
            {
                if (!c.getImage().isEmpty())
                {
                    imageTOTP = c.getImage();
                }
            }
        }
        assertEquals("dataimage", imageTOTP);
    }

    @Test
    public void testNoServiceAccount()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testWrongServerURL()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://12ds7:1nvcbn080", "test")
                                 .verifySSL(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .logger(new PILogImplementation())
                                 .realm("realm")
                                 .build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("Test");

        assertNull(responseTriggerChallenge);
    }

    @Test
    public void testNoUsername()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .serviceAccount(serviceAccount, servicePass)
                                 .logger(new PILogImplementation())
                                 .realm("realm")
                                 .build();

        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges("");

        assertNull(responseTriggerChallenge);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}