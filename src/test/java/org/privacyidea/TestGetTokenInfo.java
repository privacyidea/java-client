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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestGetTokenInfo
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "Test";
    private final String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";
    private final String serviceAccount = "admin";
    private final String servicePassword = "admin";
    private final String serviceRealm = "realm";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .serviceAccount(serviceAccount, servicePassword)
                                 .serviceRealm(serviceRealm)
                                 .disableLog()
                                 .sslVerify(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void testSuccess()
    {
        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_AUTH)
                                   .withMethod("POST")
                                   .withBody("username=" + serviceAccount + "&password=" + servicePassword + "&realm=" + serviceRealm))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));

        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withQueryStringParameter("user", username)
                                   .withPath(PIConstants.ENDPOINT_TOKEN)
                                   .withHeader("Authorization", authToken)).respond(HttpResponse.response().withBody(Utils.getTokenResponse()));

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

        assertEquals(authToken, privacyIDEA.getAuthToken());
    }

    @Test
    public void testForNoToken()
    {
        mockServer.when(HttpRequest.request()
                                   .withMethod("GET")
                                   .withQueryStringParameter("user", "Test")
                                   .withPath(PIConstants.ENDPOINT_TOKEN)
                                   .withHeader("Authorization", authToken))
                  .respond(HttpResponse.response().withBody(Utils.getTokenNoTokenResponse()));

        List<TokenInfo> tokenInfoList = privacyIDEA.getTokenInfo(username);
        assertNull(tokenInfoList);
    }

    @Test
    public void testNoServiceAccount()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false).logger(new PILogImplementation()).build();

        List<TokenInfo> tokenInfoList = privacyIDEA.getTokenInfo(username);

        assertNull(tokenInfoList);

        assertNull(privacyIDEA.getAuthToken());
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}