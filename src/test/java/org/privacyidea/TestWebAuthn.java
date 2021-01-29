package org.privacyidea;

import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.util.Optional;

import static org.junit.Assert.*;

public class TestWebAuthn implements PILoggerBridge {
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;


    @Before
    public void setup() {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = new PrivacyIDEA.Builder("https://127.0.0.1:1080", "test")
                .setSSLVerify(false)
                .setLogger(this)
                .build();
    }

    @Test
    public void test() {
        String webauthnrequest = "{\n" +
        "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";
        mockServer.when(
                HttpRequest.request()
                        .withPath(Constants.ENDPOINT_VALIDATE_CHECK)
                        .withMethod("POST")
                        .withBody("user=Test&pass=Test"))
                .respond(HttpResponse.response()
                        // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                        .withBody("{\n" +
                                "  \"detail\": {\n" +
                                "    \"attributes\": {\n" +
                                "      \"hideResponseInput\": true,\n" +
                                "      \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "      \"webAuthnSignRequest\": {\n" +
                                "        \"allowCredentials\": [\n" +
                                "          {\n" +
                                "            \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                                "            \"transports\": [\n" +
                                "              \"internal\",\n" +
                                "              \"nfc\",\n" +
                                "              \"ble\",\n" +
                                "              \"usb\"\n" +
                                "            ],\n" +
                                "            \"type\": \"public-key\"\n" +
                                "          }\n" +
                                "        ],\n" +
                                "        \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                                "        \"rpId\": \"office.netknights.it\",\n" +
                                "        \"timeout\": 60000,\n" +
                                "        \"userVerification\": \"preferred\"\n" +
                                "      }\n" +
                                "    },\n" +
                                "    \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                "    \"messages\": [\n" +
                                "      \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"\n" +
                                "    ],\n" +
                                "    \"multi_challenge\": [\n" +
                                "      {\n" +
                                "        \"attributes\": {\n" +
                                "          \"hideResponseInput\": true,\n" +
                                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "          \"webAuthnSignRequest\": " + webauthnrequest +
                                "        },\n" +
                                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                "        \"serial\": \"WAN00025CE7\",\n" +
                                "        \"transaction_id\": \"16786665691788289392\",\n" +
                                "        \"type\": \"webauthn\"\n" +
                                "      }\n" +
                                "    ],\n" +
                                "    \"serial\": \"WAN00025CE7\",\n" +
                                "    \"threadid\": 140040275289856,\n" +
                                "    \"transaction_id\": \"16786665691788289392\",\n" +
                                "    \"transaction_ids\": [\n" +
                                "      \"16786665691788289392\"\n" +
                                "    ],\n" +
                                "    \"type\": \"webauthn\"\n" +
                                "  },\n" +
                                "  \"id\": 1,\n" +
                                "  \"jsonrpc\": \"2.0\",\n" +
                                "  \"result\": {\n" +
                                "    \"status\": true,\n" +
                                "    \"value\": false\n" +
                                "  },\n" +
                                "  \"time\": 1611916339.8448942,\n" +
                                "  \"version\": \"privacyIDEA 3.5\",\n" +
                                "  \"versionnumber\": \"3.5\",\n" +
                                "  \"signature\": \"rsa_sha256_pss:0046a8c82b9063d7c9e78bac8f4accd8e1645493ced5cbf0db7a1eecdec1610b56dacb5ed12c4a6d729fbe496a4240053ab02dd2dafa407ab3b3dbd7f2dd1aeb19b6fb7a0a67a303d55d2081ff39258ed2579317601f3e09c7a2588cce7f85d15ab8b347b44c3810164a21542439f72aa2130e1cdbb1bdbc58e0aed1d8e8a265e5193601246969bb50b9d7b3486d75ca4844902e0dff80b52f370037981ac2210f405db0bc901e6333391f638a8b9315d0e34e7c56af0496b79fac25d4a8623788735dce8d450e40f4f68018883c8d81065a8492dc9894a6fbd025a199dc9a9c9f08efd7ade34ba163727a5f516ef512a14258e88c0d10bdc6c090cf62740c2b\"\n" +
                                "}\n" +
                                ""));
        PIResponse response = privacyIDEA.validateCheck("Test","Test");

        Optional <Challenge> opt = response.getMultiChallenge().stream().filter(challenge -> challenge.getType().equals("webauthn")).findFirst();
        assertTrue(opt.isPresent());
        Challenge a = opt.get();
        if (a instanceof WebAuthn) {
            WebAuthn b = (WebAuthn) a;
            assertEquals(webauthnrequest.replaceAll("\n","").replaceAll(" ",""),b.getWebAuthn());
        } else {
            fail();
        }
    }

    @Override
    public void log(String message) {

    }

    @Override
    public void error(String message) {

    }

    @Override
    public void log(Throwable t) {

    }

    @Override
    public void error(Throwable t) {

    }
}
