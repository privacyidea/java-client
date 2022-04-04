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

import java.util.Collections;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


public class TestValidateCheckSerial implements IPILogger {

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
    public void testValidateCheckSerial() {
        String responseBody = "{\n" +
                              "  \"detail\": {\n" +
                              "    \"message\": \"matching 1 tokens\",\n" +
                              "    \"otplen\": 6,\n" +
                              "    \"serial\": \"PISP0001C673\",\n" +
                              "    \"threadid\": 140536383567616,\n" +
                              "    \"type\": \"totp\"\n" +
                              "  },\n" +
                              "  \"id\": 1,\n" +
                              "  \"jsonrpc\": \"2.0\",\n" +
                              "  \"result\": {\n" +
                              "    \"status\": true,\n" +
                              "    \"value\": true\n" +
                              "  },\n" +
                              "  \"time\": 1589276995.4397042,\n" +
                              "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                              "  \"versionnumber\": \"3.2.1\",\n" +
                              "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" +
                              "}";

        mockServer.when(
                          HttpRequest.request()
                                     .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                     .withMethod("POST")
                                     .withBody("serial=PISP0001C673&pass=123456"))
                  .respond(HttpResponse.response()
                                   .withBody(responseBody));

        String serial = "PISP0001C673";
        String otp = "123456";
        String transactionID = "123";

        PIResponse response = privacyIDEA.validateCheckSerial(serial, otp, transactionID, Collections.emptyMap());
        PIResponse response1 = privacyIDEA.validateCheckSerial(serial, otp, Collections.emptyMap());
        PIResponse response2 = privacyIDEA.validateCheckSerial(serial, otp);

        assertNotNull(response);
        assertEquals(responseBody, response.toString());
        assertEquals(responseBody, response1.toString());
        assertEquals(responseBody, response2.toString());
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Override
    public void error(String message) {
        System.err.println(message);
    }

    @Override
    public void log(String message) {
        System.out.println(message);
    }

    @Override
    public void error(Throwable t) {
        t.printStackTrace();
    }

    @Override
    public void log(Throwable t) {
        t.printStackTrace();
    }
}
