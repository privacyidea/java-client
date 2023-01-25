/*
 * Copyright 2023 NetKnights GmbH - lukas.matusiewicz@netknights.it
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestValidateCheckSerial
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void testNoChallengeResponsePINPlusOTP()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("serial=PISP0001C673&pass=123456"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        String serial = "PISP0001C673";
        String pinPlusOTP = "123456";

        PIResponse response = privacyIDEA.validateCheckSerial(serial, pinPlusOTP);

        assertEquals(Utils.matchingOneToken(), response.toString());
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertTrue(response.status);
        assertTrue(response.value);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
    }

    @Test
    public void testNoChallengeResponseTransactionID()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("serial=PISP0001C673&pass=123456&transaction_id=12093809214"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        String serial = "PISP0001C673";
        String pinPlusOTP = "123456";
        String transactionID = "12093809214";

        PIResponse response = privacyIDEA.validateCheckSerial(serial, pinPlusOTP, transactionID);

        assertEquals(Utils.matchingOneToken(), response.toString());
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertTrue(response.status);
        assertTrue(response.value);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
