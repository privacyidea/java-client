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

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
                                 .serviceAccount("admin", "admin")
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void testSuccess()
    {
        String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";

        String img = "data:image/png;base64,iVBdgfgsdfgRK5CYII=";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.postAuthSuccessResponse()));


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
                                 .sslVerify(false)
                                 .logger(new PILogImplementation())
                                 .build();

        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout("games", "hotp");

        assertNull(rolloutInfo);
    }

    @Test
    public void testRolloutViaValidateCheck()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .sslVerify(false)
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
