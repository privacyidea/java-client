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
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestRollout
{
    private PrivacyIDEA privacyIDEA;
    private ClientAndServer mockServer;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .serviceAccount("admin", "admin").logger(new PILogImplementation()).build();
    }

    @Test
    public void testSuccess()
    {
        String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NoBVmAurqcaaMmwM-AsD1S6chGIM";

        String img = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";

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


        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_TOKEN_INIT).withMethod("POST")
                                   .withHeader(Header.header("Authorization", authToken))).respond(
                HttpResponse.response().withBody("{\n" + "    \"detail\": {\n" + "        \"googleurl\": {\n" +
                                                 "            \"description\": \"URL for google Authenticator\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
                                                 "            \"value\": \"otpauth://hotp/OATH0003A0AA?secret=4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH&counter=1&digits=6&issuer=privacyIDEA\"\n" +
                                                 "        },\n" + "        \"oathurl\": {\n" +
                                                 "            \"description\": \"URL for OATH token\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
                                                 "            \"value\": \"oathtoken:///addToken?name=OATH0003A0AA&lockdown=true&key=e0d5d4909065b1ba925f2583c66fd305b9816b07\"\n" +
                                                 "        },\n" + "        \"otpkey\": {\n" +
                                                 "            \"description\": \"OTP seed\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
                                                 "            \"value\": \"seed://e0d5d4909065b1ba925f2583c66fd305b9816b07\",\n" +
                                                 "            \"value_b32\": \"4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH\"\n" +
                                                 "        },\n" + "        \"rollout_state\": \"\",\n" +
                                                 "        \"serial\": \"OATH0003A0AA\",\n" +
                                                 "        \"threadid\": 140470638720768\n" + "    },\n" +
                                                 "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
                                                 "    \"result\": {\n" + "        \"status\": true,\n" +
                                                 "        \"value\": true\n" + "    },\n" +
                                                 "    \"time\": 1592834605.532012,\n" +
                                                 "    \"version\": \"privacyIDEA 3.3.3\",\n" +
                                                 "    \"versionnumber\": \"3.3.3\",\n" +
                                                 "    \"signature\": \"rsa_sha256_pss:\"\n" + "}"));

        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout("games", "hotp");

        assertEquals(img, rolloutInfo.googleurl.img);
        assertNotNull(rolloutInfo.googleurl.description);
        assertNotNull(rolloutInfo.googleurl.value);

        assertNotNull(rolloutInfo.otpkey.description);
        assertNotNull(rolloutInfo.otpkey.value);
        assertNotNull(rolloutInfo.otpkey.img);
        assertNotNull(rolloutInfo.otpkey.value_b32);

        assertNotNull(rolloutInfo.oathurl.value);
        assertNotNull(rolloutInfo.oathurl.description);
        assertNotNull(rolloutInfo.oathurl.img);

        assertNotNull(rolloutInfo.serial);
        assertTrue(rolloutInfo.rolloutState.isEmpty());
    }

    @Test
    public void testNoServiceAccount()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .logger(new PILogImplementation()).build();

        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout("games", "hotp");

        assertNull(rolloutInfo);
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
