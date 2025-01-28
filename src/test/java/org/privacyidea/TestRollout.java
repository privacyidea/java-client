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
    }

    @Test
    public void testSuccess()
    {
        String authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjNjMTZmNGUxODg2NmVmMjI1NmM3OWIwOGM1ZTkzODUzYTViMTgyMTMiLCJyb2xlIjoiYWRtaW4iLCJhdXRodHlwZSI6InBhc3N3b3JkIiwiZXhwIjoxNzM4MDY2NDc5LCJyaWdodHMiOlsidHJpZ2dlcmNoYWxsZW5nZSIsInJlc29sdmVyd3JpdGUiLCJlbnJvbGxXRUJBVVRITiIsImF1ZGl0bG9nIiwic3RhdGlzdGljc19kZWxldGUiLCJwb2xpY3lkZWxldGUiLCJlbnJvbGxWQVNDTyIsInJhZGl1c3NlcnZlcl9yZWFkIiwiZW5yb2xsU1NIS0VZIiwic210cHNlcnZlcl93cml0ZSIsImVucm9sbFFVRVNUSU9OIiwiZW5yb2xsVEFOIiwibG9zdHRva2VuIiwic3lzdGVtX2RvY3VtZW50YXRpb24iLCJzZXQiLCJlbmFibGUiLCJlbnJvbGxSRU1PVEUiLCJjb25maWdyZWFkIiwiY29weXRva2VudXNlciIsImVucm9sbFlVQklDTyIsImNvcHl0b2tlbnBpbiIsIm1yZXNvbHZlcndyaXRlIiwiaW1wb3J0dG9rZW5zIiwic2V0cGluIiwiZW5yb2xsUFVTSCIsImVucm9sbEVNQUlMIiwiY29uZmlnZGVsZXRlIiwibXJlc29sdmVycmVhZCIsInRva2VucmVhbG1zIiwiY2Fjb25uZWN0b3J3cml0ZSIsInBlcmlvZGljdGFza193cml0ZSIsImVucm9sbFBBUEVSIiwidG9rZW5saXN0Iiwic2V0X2hzbV9wYXNzd29yZCIsInJlc29sdmVyZGVsZXRlIiwiYXVkaXRsb2dfZG93bmxvYWQiLCJyZXNldCIsInNtc2dhdGV3YXlfcmVhZCIsImVucm9sbFRPVFAiLCJwb2xpY3lyZWFkIiwiZW5yb2xsWVVCSUtFWSIsInJlc29sdmVycmVhZCIsIm1hbmFnZV9tYWNoaW5lX3Rva2VucyIsImFzc2lnbiIsImdldHJhbmRvbSIsImFkZHVzZXIiLCJmZXRjaF9hdXRoZW50aWNhdGlvbl9pdGVtcyIsImVucm9sbFBXIiwibWFjaGluZWxpc3QiLCJjbGllbnR0eXBlIiwiZW5yb2xsQ0VSVElGSUNBVEUiLCJjb25maWd3cml0ZSIsImVucm9sbFNQQVNTIiwibWFuYWdlc3Vic2NyaXB0aW9uIiwiZW5yb2xsREFQTFVHIiwiZ2V0Y2hhbGxlbmdlcyIsInVzZXJsaXN0IiwiZW5yb2xsUkVHSVNUUkFUSU9OIiwiZW5yb2xsUkFESVVTIiwicmFkaXVzc2VydmVyX3dyaXRlIiwiZGVsZXRlIiwic3RhdGlzdGljc19yZWFkIiwidXBkYXRldXNlciIsImVucm9sbFRJUVIiLCJzbXRwc2VydmVyX3JlYWQiLCJlbnJvbGxwaW4iLCJ1bmFzc2lnbiIsImNhY29ubmVjdG9yZGVsZXRlIiwiZW5yb2xsTU9UUCIsImdldHNlcmlhbCIsInJlc3luYyIsImVucm9sbDRFWUVTIiwiZW5yb2xsT0NSQSIsInNtc2dhdGV3YXlfd3JpdGUiLCJlbnJvbGxIT1RQIiwiZXZlbnRoYW5kbGluZ19yZWFkIiwiZXZlbnRoYW5kbGluZ193cml0ZSIsInByaXZhY3lpZGVhc2VydmVyX3dyaXRlIiwibXJlc29sdmVyZGVsZXRlIiwicHJpdmFjeWlkZWFzZXJ2ZXJfcmVhZCIsImVucm9sbFUyRiIsInJldm9rZSIsInBlcmlvZGljdGFza19yZWFkIiwicG9saWN5d3JpdGUiLCJkaXNhYmxlIiwiZGVsZXRldXNlciIsImVucm9sbFNNUyIsInNldHRva2VuaW5mbyJdfQ.bgxeEFPcwTY9V8jxLHtDQPGlmfxewc7HSV29Hutd3H8";
        String img = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       .withBody(Utils.postAuthSuccessResponse()));

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .serviceAccount("admin", "admin")
                                 .logger(new PILogImplementation())
                                 .build();

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_TOKEN_INIT)
                                   .withMethod("POST")
                                   .withHeader(Header.header("Authorization", authToken)))
                  .respond(HttpResponse.response()
                                       .withBody(Utils.rolloutSuccess()));

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
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();

        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout("games", "hotp");

        assertNull(rolloutInfo);
    }

    @Test
    public void testRolloutViaValidateCheck()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();

        String image = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";
        String username = "testuser";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=" + username + "&pass="))
                  .respond(HttpResponse.response().withBody(Utils.rolloutViaChallenge()));

        PIResponse responseValidateCheck = privacyIDEA.validateCheck(username, "");

        assertEquals(image, responseValidateCheck.image);
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
