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
    public void testSuccess()
    {
        String webauthnSignResponse =
                "{" + "\"credentialid\":\"X9FrwMfmzj...saw21\"," + "\"authenticatordata\":\"xGzvgAAACA\"," +
                "\"clientdata\":\"eyJjaGFsbG...dfhs\"," + "\"signaturedata\":\"MEUCIQDNrG...43hc\"," +
                "\"assertionclientextensions\":\"alsjdlfkjsadjeiw\"," + "\"userhandle\":\"jalsdkjflsjvccco2\"\n" + "}";

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_VALIDATE_CHECK)
                                   .withMethod("POST")
                                   .withBody("user=Test&transaction_id=16786665691788289392&pass=" +
                                             "&credentialid=X9FrwMfmzj...saw21&clientdata=eyJjaGFsbG...dfhs&signaturedata=MEUCIQDNrG...43hc" +
                                             "&authenticatordata=xGzvgAAACA&userhandle=jalsdkjflsjvccco2&assertionclientextensions=alsjdlfkjsadjeiw"))
                  .respond(HttpResponse.response().withBody(Utils.matchingOneToken()));

        PIResponse response = privacyIDEA.validateCheckWebAuthn("Test", "16786665691788289392", webauthnSignResponse, "test.it");

        assertNotNull(response);
        assertEquals("matching 1 tokens", response.message);
        assertEquals("PISP0001C673", response.serial);
        assertEquals("totp", response.type);
        assertEquals(1, response.id);
        assertEquals("2.0", response.jsonRPCVersion);
        assertEquals("3.2.1", response.piVersion);
        assertEquals("rsa_sha256_pss:AAAAAAAAAAA", response.signature);
        assertEquals(6, response.otpLength);
        assertTrue(response.status);
        assertTrue(response.value);
    }

    @Test
    public void testTriggerWebAuthn()
    {
        String username = "Test";
        String pass = "Test";

        mockServer.when(
                          HttpRequest.request().withPath(PIConstants.ENDPOINT_VALIDATE_CHECK).withMethod("POST").withBody("user=" + username + "&pass=" + pass))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody(Utils.triggerWebauthn()));

        PIResponse response = privacyIDEA.validateCheck(username, pass);

        Optional<Challenge> opt = response.multiChallenge.stream().filter(challenge -> TOKEN_TYPE_WEBAUTHN.equals(challenge.getType())).findFirst();
        assertTrue(opt.isPresent());
        assertEquals(AuthenticationStatus.CHALLENGE, response.authentication);
        assertEquals("webauthn", response.preferredClientMode);
        Challenge a = opt.get();
        /*
        if (a instanceof WebAuthn)
        {
            WebAuthn b = (WebAuthn) a;
            String trimmedRequest = Utils.webauthnSignRequest().replaceAll("\n", "").replaceAll(" ", "");
            assertEquals(trimmedRequest, b.signRequest());
            assertEquals("static/img/FIDO-U2F-Security-Key-444x444.png", b.getImage());
            assertEquals("webauthn", b.getClientMode());
        }
        else
        {
            fail();
        }
        */
    }

    @Test
    public void testMergedSignRequestSuccess()
    {
        JSONParser jsonParser = new JSONParser(privacyIDEA);
        PIResponse piResponse1 = jsonParser.parsePIResponse(Utils.multipleWebauthnResponse());
        String trimmedRequest = Utils.expectedMergedResponse().replaceAll("\n", "").replaceAll(" ", "");
        String merged1 = piResponse1.mergedSignRequest();

        assertEquals(trimmedRequest, merged1);

        // short test otpMessage()
        String otpMessage = piResponse1.otpMessage();

        assertEquals("Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), " +
                     "Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", otpMessage);
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