package org.privacyidea;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;

public class TestServiceAccount implements PILoggerBridge {
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    private final String username = "testuser";
    private final String otp = "123456";

    private final String serviceUser = "admin";
    private final String servicePass = "admin";

    private Throwable lastError;

    @Before
    public void setup() {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = new PrivacyIDEA.Builder("https://127.0.0.1:1080", "test")
                .setServiceAccount(serviceUser, servicePass)
                .setSSLVerify(false)
                .setLogger(this)
                .build();
    }

    @Test
    public void testGettingAuthToken() {
        String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU" +
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

        mockServer.when(
                HttpRequest.request()
                        .withPath(Constants.ENDPOINT_AUTH)
                        .withMethod("POST")
                        .withBody(""))
                .respond(HttpResponse.response()
                        // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                        .withBody("{\n" +
                                "    \"id\": 1,\n" +
                                "    \"jsonrpc\": \"2.0\",\n" +
                                "    \"result\": {\n" +
                                "        \"status\": true,\n" +
                                "        \"value\": {\n" +
                                "            \"log_level\": 20,\n" +
                                "            \"menus\": [\n" +
                                "                \"components\",\n" +
                                "                \"machines\"\n" +
                                "            ],\n" +
                                "            \"realm\": \"\",\n" +
                                "            \"rights\": [\n" +
                                "                \"policydelete\",\n" +
                                "                \"resync\"\n" +
                                "            ],\n" +
                                "            \"role\": \"admin\",\n" +
                                "            \"token\": \"" + authToken + "\",\n" +
                                "            \"username\": \"admin\",\n" +
                                "            \"logout_time\": 120,\n" +
                                "            \"default_tokentype\": \"hotp\",\n" +
                                "            \"user_details\": false,\n" +
                                "            \"subscription_status\": 0\n" +
                                "        }\n" +
                                "    },\n" +
                                "    \"time\": 1589446794.8502703,\n" +
                                "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                "    \"versionnumber\": \"3.2.1\",\n" +
                                "    \"signature\": \"rsa_sha256_pss:\"\n" +
                                "}"));

        String retAuthToken = privacyIDEA.getAuthToken();
        assertEquals(authToken, retAuthToken);
    }

    @After
    public void tearDown() {
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
        lastError = t;
    }

    @Override
    public void log(Throwable t) {
        t.printStackTrace();
        lastError = t;
    }
}
