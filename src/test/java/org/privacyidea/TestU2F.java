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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.privacyidea.PIConstants.TOKEN_TYPE_U2F;

public class TestU2F
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

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void testTriggerU2F()
    {
        String responseBody = "{" + "\"detail\":{" + "\"attributes\":{" + "\"hideResponseInput\":true," +
                              "\"img\":\"static/img/FIDO-U2F-Security-Key-444x444.png\"," + "\"u2fSignRequest\":{" +
                              "\"appId\":\"http//ttype.u2f\"," +
                              "\"challenge\":\"TZKiB0VFFMF...tQduDJf56AeJAY_BT4NU\"," +
                              "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQ...qzZW1lC-jDdFd2pKDUsNnA\"," +
                              "\"version\":\"U2F_V2\"}}," +
                              "\"message\":\"Please confirm with your U2F token (Yubico U2F EE Serial 61730834)\"," +
                              "\"messages\":[\"Please confirm with your U2F token (Yubico U2F EE Serial 61730834)\"]," +
                              "\"multi_challenge\":[{" + "\"attributes\":{" + "\"hideResponseInput\":true," +
                              "\"img\":\"static/img/FIDO-U2F-Security-Key-444x444.png\"," + "\"u2fSignRequest\":{" +
                              "\"appId\":\"https://ttype.u2f\"," +
                              "\"challenge\":\"TZKiB0VFFMFsnlz00lF5iCqtQduDJf56AeJAY_BT4NU\"," +
                              "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQJYu4G5qB9l7ScjRRxA-M35cTH-uHWyMEpxs4WBzbkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                              "\"version\":\"U2F_V2\"}}," +
                              "\"message\":\"Please confirm with your U2F token (Yubico U2F EE Serial 61730834)\"," +
                              "\"serial\":\"U2F00014651\"," + "\"transaction_id\":\"12399202888279169736\"," +
                              "\"type\":\"u2f\"}]," + "\"serial\":\"U2F00014651\"," + "\"threadid\":140050978137856," +
                              "\"transaction_id\":\"12399202888279169736\"," +
                              "\"transaction_ids\":[\"12399202888279169736\"]," + "\"type\":\"u2f\"}," + "\"id\":1," +
                              "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," +
                              "\"time\":1649769348.7552881," + "\"version\":\"privacyIDEA 3.6.3\"," +
                              "\"versionnumber\":\"3.6.3\"," +
                              "\"signature\":\"rsa_sha256_pss:3e51d814...dccd5694b8c15943e37e1\"}";

        String u2fSignRequest = "{" + "\"appId\":\"https://ttype.u2f\"," +
                                "\"challenge\":\"TZKiB0VFFMFsnlz00lF5iCqtQduDJf56AeJAY_BT4NU\"," +
                                "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQJYu4G5qB9l7ScjRRxA-M35cTH-uHWyMEpxs4WBzbkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                "\"version\":\"U2F_V2\"" + "}";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&pass=test"))
                  .respond(HttpResponse.response().withBody(responseBody));

        PIResponse response = privacyIDEA.validateCheck("Test", "test");

        assertEquals(1, response.id);
        assertEquals("Please confirm with your U2F token (Yubico U2F EE Serial 61730834)", response.message);
        assertEquals(0, response.otpLength);
        assertEquals("U2F00014651", response.serial);
        assertEquals("u2f", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.6.3", response.piVersion);
        assertEquals("rsa_sha256_pss:3e51d814...dccd5694b8c15943e37e1", response.signature);
        assertTrue(response.status);
        assertFalse(response.value);

        Optional<Challenge> opt = response.multichallenge.stream()
                                                         .filter(challenge -> TOKEN_TYPE_U2F.equals(challenge.getType()))
                                                         .findFirst();
        if (opt.isPresent())
        {
            Challenge a = opt.get();
            if (a instanceof U2F)
            {
                U2F b = (U2F) a;
                String trimmedRequest = u2fSignRequest.replaceAll("\n", "").replaceAll(" ", "");
                assertEquals(trimmedRequest, b.signRequest());
            }
            else
            {
                fail();
            }
        }
        else
        {
            fail();
        }
    }

    @Test
    public void testSuccess()
    {
        String username = "Test";

        String responseBody =
                "{\n" + "  \"detail\": {\n" + "    \"message\": \"matching 1 tokens\",\n" + "    \"otplen\": 6,\n" +
                "    \"serial\": \"PISP0001C673\",\n" + "    \"threadid\": 140536383567616,\n" +
                "    \"type\": \"totp\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" + "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" +
                "  \"time\": 1589276995.4397042,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" + "}";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&transaction_id=16786665691788289392&pass=" +
                                             "&clientdata=eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ" +
                                             "&signaturedata=AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg"))
                  .respond(HttpResponse.response().withBody(responseBody));

        String u2fSignResponse = "{\"clientData\":\"eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ\"," + "\"errorCode\":0," +
                                 "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                 "\"signatureData\":\"AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg\"}";

        Map<String, String> header = new HashMap<>();
        header.put("accept-language", "en");
        PIResponse response = privacyIDEA.validateCheckU2F(username, "16786665691788289392", u2fSignResponse, header);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testSuccessWithoutHeader()
    {
        String username = "Test";

        String responseBody =
                "{\n" + "  \"detail\": {\n" + "    \"message\": \"matching 1 tokens\",\n" + "    \"otplen\": 6,\n" +
                "    \"serial\": \"PISP0001C673\",\n" + "    \"threadid\": 140536383567616,\n" +
                "    \"type\": \"totp\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" + "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" +
                "  \"time\": 1589276995.4397042,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" + "}";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&transaction_id=16786665691788289392&pass=" +
                                             "&clientdata=eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ" +
                                             "&signaturedata=AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg"))
                  .respond(HttpResponse.response().withBody(responseBody));

        String u2fSignResponse = "{\"clientData\":\"eyJjaGFsbGVuZ2UiOiJpY2UBc3NlcnRpb24ifQ\"," + "\"errorCode\":0," +
                                 "\"keyHandle\":\"UUHmZ4BUFCrt7q88MhlQkjlZqzZW1lC-jDdFd2pKDUsNnA\"," +
                                 "\"signatureData\":\"AQAAAxAwRQIgZwEObruoCRRo738F9up1tdV2M0H1MdP5pkO5Eg\"}";

        PIResponse response = privacyIDEA.validateCheckU2F(username, "16786665691788289392", u2fSignResponse);

        assertEquals(1, response.id);
        assertEquals("matching 1 tokens", response.message);
        assertEquals(6, response.otpLength);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertTrue(response.status);
        assertTrue(response.value);
    }
}