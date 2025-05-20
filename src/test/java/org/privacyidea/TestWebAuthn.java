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

import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import shaded_package.org.apache.commons.lang3.StringUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;

public class TestWebAuthn
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").verifySSL(false).logger(new PILogImplementation()).build();
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void testTriggerWebAuthn()
    {
        String username = "Test";
        String pass = "Test";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=" + username + "&pass=" + pass)).respond(HttpResponse.response()
                                                                                                        // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                                                                                        .withBody(Utils.triggerWebauthn()));

        PIResponse response = privacyIDEA.validateCheck(username, pass);
        assertEquals(AuthenticationStatus.CHALLENGE, response.authentication);
        assertEquals("webauthn", response.preferredClientMode);
        assertTrue(response.webAuthnSignRequest != null && !response.webAuthnSignRequest.isEmpty());
    }

    @Test
    public void testMergedSignRequestSuccess()
    {
        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(Utils.multipleWebauthnResponse());
        String trimmedRequest = Utils.expectedMergedResponse().replaceAll("\n", "").replaceAll(" ", "");
        String merged1 = piResponse1.mergedSignRequest();

        assertEquals(trimmedRequest, merged1);
        assertEquals("Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), " +
                     "Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", piResponse1.message);
    }

    @Test
    public void testMergedSignRequestEmpty()
    {
        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(Utils.mergedSignRequestEmpty());
        String empty1 = piResponse1.mergedSignRequest();

        assertEquals("", empty1);
    }

    @Test
    public void testMergedSignRequestIncompleteSignRequest()
    {
        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(Utils.mergedSignRequestIncomplete());
        String trimmedRequest = Utils.expectedMergedResponseIncomplete().replaceAll("\n", "").replaceAll(" ", "");
        String merged1 = piResponse1.mergedSignRequest();

        assertEquals(trimmedRequest, merged1);
    }
}