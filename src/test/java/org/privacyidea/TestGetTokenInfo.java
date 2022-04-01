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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestGetTokenInfo implements IPILogger
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "Test";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        String serviceUser = "admin";
        String servicePass = "admin";
        String realm = "realm";

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").serviceAccount(serviceUser, servicePass)
                                 .realm(realm).sslVerify(false).logger(this).build();
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void test()
    {
        String result = "{\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":{" +
                        "\"count\":1," + "\"current\":1," + "\"tokens\":[{" + "\"active\":true," + "\"count\":2," +
                        "\"count_window\":10," + "\"description\":\"\"," + "\"failcount\":0," + "\"id\":347," +
                        "\"info\":{" + "\"count_auth\":\"1\"," + "\"count_auth_success\":\"1\"," +
                        "\"hashlib\":\"sha1\"," + "\"last_auth\":\"2022-03-2912:18:59.639421+02:00\"," +
                        "\"tokenkind\":\"software\"}," + "\"locked\":false," + "\"maxfail\":10," + "\"otplen\":6," +
                        "\"realms\":[\"defrealm\"]," + "\"resolver\":\"deflocal\"," + "\"revoked\":false," +
                        "\"rollout_state\":\"\"," + "\"serial\":\"OATH00123564\"," + "\"sync_window\":1000," +
                        "\"tokentype\":\"hotp\"," + "\"user_editable\":false," + "\"user_id\":\"5\"," +
                        "\"user_realm\":\"defrealm\"," + "\"username\":\"Test\"}]}}," + "\"time\":1648549489.57896," +
                        "\"version\":\"privacyIDEA3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
                        "\"signature\":\"rsa_sha256_pss:58c4eed1...5247c47e3e\"}";

        String authToken =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU" +
                "4ZDVhODY5YzUzNGI5ZmY1MWFmNzI2ZjI5OTE2YmYiLCJyb2xlIjoiYWRtaW4iLCJhdXRodHlwZSI6InBhc3N3b3JkIiwiZXhwIjoxNTg5NDUwMzk0LC" +
                "JyaWdodHMiOlsicG9saWN5ZGVsZXRlIiwic3RhdGlzdGljc19yZWFkIiwiYXVkaXRsb2ciLCJlbmFibGUiLCJ1c2VybGlzdCIsInVwZGF0ZXVzZXIiL" +
                "CJhZGR1c2VyIiwiZW5yb2xsU1BBU1MiLCJjYWNvbm5lY3RvcndyaXRlIiwidW5hc3NpZ24iLCJkZWxldGV1c2VyIiwic2V0cGluIiwiZGlzYWJsZSIs" +
                "ImVucm9sbFNTSEtFWSIsImZldGNoX2F1dGhlbnRpY2F0aW9uX2l0ZW1zIiwicHJpdmFjeWlkZWFzZXJ2ZXJfcmVhZCIsImdldHJhbmRvbSIsImVucm9" +
                "sbFNNUyIsIm1yZXNvbHZlcndyaXRlIiwicmFkaXVzc2VydmVyX3dyaXRlIiwiaW1wb3J0dG9rZW5zIiwic2V0X2hzbV9wYXNzd29yZCIsImVucm9sbF" +
                "JFTU9URSIsImVucm9sbFUyRiIsInByaXZhY3lpZGVhc2VydmVyX3dyaXRlIiwiZW5yb2xsUkFESVVTIiwiY29weXRva2VucGluIiwiZW5yb2xsRU1BS" +
                "UwiLCJyZXNldCIsImNhY29ubmVjdG9yZGVsZXRlIiwiZW5yb2xsVkFTQ08iLCJlbnJvbGxSRUdJU1RSQVRJT04iLCJzZXQiLCJnZXRzZXJpYWwiLCJw" +
                "ZXJpb2RpY3Rhc2tfcmVhZCIsImV2ZW50aGFuZGxpbmdfd3JpdGUiLCJtcmVzb2x2ZXJkZWxldGUiLCJyZXNvbHZlcmRlbGV0ZSIsInNtdHBzZXJ2ZXJ" +
                "fd3JpdGUiLCJyYWRpdXNzZXJ2ZXJfcmVhZCIsImVucm9sbDRFWUVTIiwiZW5yb2xsUEFQRVIiLCJlbnJvbGxZVUJJQ08iLCJnZXRjaGFsbGVuZ2VzIi" +
                "wibWFuYWdlc3Vic2NyaXB0aW9uIiwibG9zdHRva2VuIiwiZGVsZXRlIiwiZW5yb2xscGluIiwic21zZ2F0ZXdheV93cml0ZSIsImVucm9sbFBVU0giL" +
                "CJlbnJvbGxNT1RQIiwibWFuYWdlX21hY2hpbmVfdG9rZW5zIiwic3lzdGVtX2RvY3VtZW50YXRpb24iLCJtYWNoaW5lbGlzdCIsInRyaWdnZXJjaGFs" +
                "bGVuZ2UiLCJzdGF0aXN0aWNzX2RlbGV0ZSIsInJlc29sdmVyd3JpdGUiLCJjbGllbnR0eXBlIiwic2V0dG9rZW5pbmZvIiwiZW5yb2xsT0NSQSIsImF" +
                "1ZGl0bG9nX2Rvd25sb2FkIiwiZW5yb2xsUFciLCJlbnJvbGxIT1RQIiwiZW5yb2xsVEFOIiwiZXZlbnRoYW5kbGluZ19yZWFkIiwiY29weXRva2VudX" +
                "NlciIsInRva2VubGlzdCIsInNtdHBzZXJ2ZXJfcmVhZCIsImVucm9sbERBUExVRyIsInJldm9rZSIsImVucm9sbFRPVFAiLCJjb25maWdyZWFkIiwiY" +
                "29uZmlnd3JpdGUiLCJzbXNnYXRld2F5X3JlYWQiLCJlbnJvbGxRVUVTVElPTiIsInRva2VucmVhbG1zIiwiZW5yb2xsVElRUiIsInBvbGljeXJlYWQi" +
                "LCJtcmVzb2x2ZXJyZWFkIiwicGVyaW9kaWN0YXNrX3dyaXRlIiwicG9saWN5d3JpdGUiLCJyZXNvbHZlcnJlYWQiLCJlbnJvbGxDRVJUSUZJQ0FURSI" +
                "sImFzc2lnbiIsImNvbmZpZ2RlbGV0ZSIsImVucm9sbFlVQklLRVkiLCJyZXN5bmMiXX0.HvP_hgA-UJFINXnwoBVmAurqcaaMmwM-AsD1S6chGIM";

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

        mockServer.when(HttpRequest.request().withMethod("GET").withQueryStringParameter("user", "Test")
                                   .withPath(PIConstants.ENDPOINT_TOKEN).withHeader("Authorization", authToken))
                  .respond(HttpResponse.response().withBody(result));

        List<TokenInfo> tokenInfoList = privacyIDEA.getTokenInfo(username);
        assertNotNull(tokenInfoList);
        assertEquals(tokenInfoList.size(), 1);

        TokenInfo tokenInfo = tokenInfoList.get(0);
        assertTrue(tokenInfo.active);
        assertEquals(2, tokenInfo.count);
        assertEquals(10, tokenInfo.countWindow);
        assertEquals("", tokenInfo.description);
        assertEquals(0, tokenInfo.failCount);
        assertEquals(347, tokenInfo.id);
        assertFalse(tokenInfo.locked);
        assertEquals(10, tokenInfo.maxFail);
        assertEquals(6, tokenInfo.otpLen);
        assertEquals("deflocal", tokenInfo.resolver);
        assertFalse(tokenInfo.revoked);
        assertEquals("", tokenInfo.rolloutState);
        assertEquals("OATH00123564", tokenInfo.serial);
        assertEquals(1000, tokenInfo.syncWindow);
        assertEquals("hotp", tokenInfo.tokenType);
        assertFalse(tokenInfo.userEditable);
        assertEquals("5", tokenInfo.userID);
        assertEquals("defrealm", tokenInfo.userRealm);
        assertEquals("Test", tokenInfo.username);
    }

    @Test
    public void testForNoToken()
    {
        String resultNoTokens =
                "{\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":{" +
                "\"count\":0," + "\"current\":1," + "\"tokens\":[]}}," + "\"time\":1648548984.9165428," +
                "\"version\":\"privacyIDEA3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
                "\"signature\":\"rsa_sha256_pss:5295e005a48b0a915a1e37f80\"}";

        String authToken =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU" +
                "4ZDVhODY5YzUzNGI5ZmY1MWFmNzI2ZjI5OTE2YmYiLCJyb2xlIjoiYWRtaW4iLCJhdXRodHlwZSI6InBhc3N3b3JkIiwiZXhwIjoxNTg5NDUwMzk0LC" +
                "JyaWdodHMiOlsicG9saWN5ZGVsZXRlIiwic3RhdGlzdGljc19yZWFkIiwiYXVkaXRsb2ciLCJlbmFibGUiLCJ1c2VybGlzdCIsInVwZGF0ZXVzZXIiL" +
                "CJhZGR1c2VyIiwiZW5yb2xsU1BBU1MiLCJjYWNvbm5lY3RvcndyaXRlIiwidW5hc3NpZ24iLCJkZWxldGV1c2VyIiwic2V0cGluIiwiZGlzYWJsZSIs" +
                "ImVucm9sbFNTSEtFWSIsImZldGNoX2F1dGhlbnRpY2F0aW9uX2l0ZW1zIiwicHJpdmFjeWlkZWFzZXJ2ZXJfcmVhZCIsImdldHJhbmRvbSIsImVucm9" +
                "sbFNNUyIsIm1yZXNvbHZlcndyaXRlIiwicmFkaXVzc2VydmVyX3dyaXRlIiwiaW1wb3J0dG9rZW5zIiwic2V0X2hzbV9wYXNzd29yZCIsImVucm9sbF" +
                "JFTU9URSIsImVucm9sbFUyRiIsInByaXZhY3lpZGVhc2VydmVyX3dyaXRlIiwiZW5yb2xsUkFESVVTIiwiY29weXRva2VucGluIiwiZW5yb2xsRU1BS" +
                "UwiLCJyZXNldCIsImNhY29ubmVjdG9yZGVsZXRlIiwiZW5yb2xsVkFTQ08iLCJlbnJvbGxSRUdJU1RSQVRJT04iLCJzZXQiLCJnZXRzZXJpYWwiLCJw" +
                "ZXJpb2RpY3Rhc2tfcmVhZCIsImV2ZW50aGFuZGxpbmdfd3JpdGUiLCJtcmVzb2x2ZXJkZWxldGUiLCJyZXNvbHZlcmRlbGV0ZSIsInNtdHBzZXJ2ZXJ" +
                "fd3JpdGUiLCJyYWRpdXNzZXJ2ZXJfcmVhZCIsImVucm9sbDRFWUVTIiwiZW5yb2xsUEFQRVIiLCJlbnJvbGxZVUJJQ08iLCJnZXRjaGFsbGVuZ2VzIi" +
                "wibWFuYWdlc3Vic2NyaXB0aW9uIiwibG9zdHRva2VuIiwiZGVsZXRlIiwiZW5yb2xscGluIiwic21zZ2F0ZXdheV93cml0ZSIsImVucm9sbFBVU0giL" +
                "CJlbnJvbGxNT1RQIiwibWFuYWdlX21hY2hpbmVfdG9rZW5zIiwic3lzdGVtX2RvY3VtZW50YXRpb24iLCJtYWNoaW5lbGlzdCIsInRyaWdnZXJjaGFs" +
                "bGVuZ2UiLCJzdGF0aXN0aWNzX2RlbGV0ZSIsInJlc29sdmVyd3JpdGUiLCJjbGllbnR0eXBlIiwic2V0dG9rZW5pbmZvIiwiZW5yb2xsT0NSQSIsImF" +
                "1ZGl0bG9nX2Rvd25sb2FkIiwiZW5yb2xsUFciLCJlbnJvbGxIT1RQIiwiZW5yb2xsVEFOIiwiZXZlbnRoYW5kbGluZ19yZWFkIiwiY29weXRva2VudX" +
                "NlciIsInRva2VubGlzdCIsInNtdHBzZXJ2ZXJfcmVhZCIsImVucm9sbERBUExVRyIsInJldm9rZSIsImVucm9sbFRPVFAiLCJjb25maWdyZWFkIiwiY" +
                "29uZmlnd3JpdGUiLCJzbXNnYXRld2F5X3JlYWQiLCJlbnJvbGxRVUVTVElPTiIsInRva2VucmVhbG1zIiwiZW5yb2xsVElRUiIsInBvbGljeXJlYWQi" +
                "LCJtcmVzb2x2ZXJyZWFkIiwicGVyaW9kaWN0YXNrX3dyaXRlIiwicG9saWN5d3JpdGUiLCJyZXNvbHZlcnJlYWQiLCJlbnJvbGxDRVJUSUZJQ0FURSI" +
                "sImFzc2lnbiIsImNvbmZpZ2RlbGV0ZSIsImVucm9sbFlVQklLRVkiLCJyZXN5bmMiXX0.HvP_hgA-UJFINXnwoBVmAurqcaaMmwM-AsD1S6chGIM";

        mockServer.when(HttpRequest.request().withMethod("GET").withQueryStringParameter("user", "Test")
                                   .withPath(PIConstants.ENDPOINT_TOKEN).withHeader("Authorization", authToken))
                  .respond(HttpResponse.response().withBody(resultNoTokens));

        List<TokenInfo> tokenInfoList = privacyIDEA.getTokenInfo(username);
        assertNull(tokenInfoList);
    }

    @Override
    public void log(String message)
    {
        System.out.println(message);
    }

    @Override
    public void error(String message)
    {
        System.err.println(message);
    }

    @Override
    public void log(Throwable t)
    {
        System.out.println(t.getMessage());
    }

    @Override
    public void error(Throwable t)
    {
        System.err.println(t.getMessage());
    }
}
