package org.privacyidea;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

public class TestCRnoServiceAcc implements IPILogger {

    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    private final String username = "testuser";
    private final String otp = "123456";

    private final AtomicBoolean waitingForCallback = new AtomicBoolean(true);

    @Before
    public void setup() {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = new PrivacyIDEA.Builder("https://127.0.0.1:1080", "test")
                .setSSLVerify(false)
                .setLogger(this)
                .setSimpleLogger(System.out::println)
                .build();
    }

    @Test
    public void testPushSynchronous() throws InterruptedException {
        // Set the initial "challenges triggered" response, pass is empty here
        // How the challenge is triggered depends on the configuration of the privacyIDEA server
        mockServer.when(
                HttpRequest.request()
                        .withMethod("POST")
                        .withPath("/validate/check")
                        .withBody("user=" + username + "&pass="))
                .respond(HttpResponse.response()
                        .withContentType(MediaType.APPLICATION_JSON)
                        .withBody("{\n" +
                                "  \"detail\": {\n" +
                                "    \"attributes\": null,\n" +
                                "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
                                "    \"messages\": [\n" +
                                "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                "      \"Please confirm the authentication on your mobile device!\"\n" +
                                "    ],\n" +
                                "    \"multi_challenge\": [\n" +
                                "      {\n" +
                                "        \"attributes\": null,\n" +
                                "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                "        \"serial\": \"OATH00020121\",\n" +
                                "        \"transaction_id\": \"02659936574063359702\",\n" +
                                "        \"type\": \"hotp\"\n" +
                                "      },\n" +
                                "      {\n" +
                                "        \"attributes\": null,\n" +
                                "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
                                "        \"serial\": \"PIPU0001F75E\",\n" +
                                "        \"transaction_id\": \"02659936574063359702\",\n" +
                                "        \"type\": \"push\"\n" +
                                "      }\n" +
                                "    ],\n" +
                                "    \"serial\": \"PIPU0001F75E\",\n" +
                                "    \"threadid\": 140040525666048,\n" +
                                "    \"transaction_id\": \"02659936574063359702\",\n" +
                                "    \"transaction_ids\": [\n" +
                                "      \"02659936574063359702\",\n" +
                                "      \"02659936574063359702\"\n" +
                                "    ],\n" +
                                "    \"type\": \"push\"\n" +
                                "  },\n" +
                                "  \"id\": 1,\n" +
                                "  \"jsonrpc\": \"2.0\",\n" +
                                "  \"result\": {\n" +
                                "    \"status\": true,\n" +
                                "    \"value\": false\n" +
                                "  },\n" +
                                "  \"time\": 1589360175.594304,\n" +
                                "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                                "  \"versionnumber\": \"3.2.1\",\n" +
                                "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" +
                                "}")
                        .withDelay(TimeUnit.MILLISECONDS, 50));

        PIResponse initialResponse = privacyIDEA.validateCheck(username, null);

        // Check the triggered challenges - the other things are already tested in org.privacyidea.TestOTP
        List<Challenge> challenges = initialResponse.getMultiChallenge();

        Challenge hotpChallenge = challenges.stream().filter(c -> c.getSerial().equals("OATH00020121")).findFirst().orElse(null);
        assertNotNull(hotpChallenge);
        assertEquals("Bitte geben Sie einen OTP-Wert ein: ", hotpChallenge.getMessage());
        assertEquals("02659936574063359702", hotpChallenge.getTransactionID());
        assertEquals("hotp", hotpChallenge.getType());
        assertTrue(hotpChallenge.getAttributes().isEmpty());

        Challenge pushChallenge = challenges.stream().filter(c -> c.getSerial().equals("PIPU0001F75E")).findFirst().orElse(null);
        assertNotNull(pushChallenge);
        assertEquals("Please confirm the authentication on your mobile device!", pushChallenge.getMessage());
        assertEquals("02659936574063359702", pushChallenge.getTransactionID());
        assertEquals("push", pushChallenge.getType());
        assertTrue(pushChallenge.getAttributes().isEmpty());

        List<String> triggeredTypes = initialResponse.getTriggeredTokenTypes();
        assertTrue(triggeredTypes.contains("push"));
        assertTrue(triggeredTypes.contains("hotp"));

        List<String> transactionIDs = initialResponse.getTransactionIDs();
        assertEquals(1, transactionIDs.size());
        assertTrue(transactionIDs.contains(initialResponse.getTransactionID()));

        assertEquals(2, initialResponse.getMessages().size());

        // Set the server up to respond to the polling requests twice with false
        setPollTransactionResponse(false, 2);

        // Polling is controlled by the code using the sdk
        for (int i = 0; i < 2; i++) {
            assertFalse(privacyIDEA.pollTransaction(initialResponse.getTransactionID()));
            Thread.sleep(500);
        }

        // Set the server to respond with true
        setPollTransactionResponse(true, 1);
        assertTrue(privacyIDEA.pollTransaction(initialResponse.getTransactionID()));

        // Now the transaction has to be finalized manually
        setFinalizationResponse(initialResponse.getTransactionID());

        PIResponse response = privacyIDEA.validateCheck(username, null, initialResponse.getTransactionID());
        assertTrue(response.getValue());
    }

    @Test
    public void testPushAsync() {
        // Skip the inital triggering
        // Since everything is done automatically, setup the responses at the start
        // 3x polling false, then true, then a /validate/check response for the finalization
        setPollTransactionResponse(false, 3);
        setPollTransactionResponse(true, 1);
        setFinalizationResponse("02659936574063359702"); // fixed for all tests

        privacyIDEA.asyncPollTransaction("02659936574063359702", username, response -> {
            assertTrue(response.getValue());
            waitingForCallback.set(false);
        });

        while (waitingForCallback.get()) {
        }

    }

    @After
    public void tearDown() {
        mockServer.stop();
    }

    private void setFinalizationResponse(String transactionID) {
        mockServer.when(
                HttpRequest.request()
                        .withMethod("POST")
                        .withPath("/validate/check")
                        .withBody("user=" + username + "&pass=&transaction_id=" + transactionID))
                .respond(HttpResponse.response()
                        .withBody("{\n" +
                                "    \"detail\": {\n" +
                                "        \"message\": \"Found matching challenge\",\n" +
                                "        \"serial\": \"PIPU0001F75E\",\n" +
                                "        \"threadid\": 140586038396672\n" +
                                "    },\n" +
                                "    \"id\": 1,\n" +
                                "    \"jsonrpc\": \"2.0\",\n" +
                                "    \"result\": {\n" +
                                "        \"status\": true,\n" +
                                "        \"value\": true\n" +
                                "    },\n" +
                                "    \"time\": 1589446811.2747126,\n" +
                                "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                "    \"versionnumber\": \"3.2.1\",\n" +
                                "    \"signature\": \"rsa_sha256_pss:\"\n" +
                                "}"));
    }

    private void setPollTransactionResponse(boolean value, int times) {
        String val = value ? "true" : "false";
        mockServer.when(
                HttpRequest.request()
                        .withMethod("GET")
                        .withPath("/validate/polltransaction") //?transaction_id=02659936574063359702
                , Times.exactly(times))
                .respond(
                        HttpResponse.response()
                                .withBody("{\n" +
                                        "    \"id\": 1,\n" +
                                        "    \"jsonrpc\": \"2.0\",\n" +
                                        "    \"result\": {\n" +
                                        "        \"status\": true,\n" +
                                        "        \"value\": " + val + "\n" +
                                        "    },\n" +
                                        "    \"time\": 1589446811.1909237,\n" +
                                        "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                        "    \"versionnumber\": \"3.2.1\",\n" +
                                        "    \"signature\": \"rsa_sha256_pss:\"\n" +
                                        "}")
                                .withDelay(TimeUnit.MILLISECONDS, 50));
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
    }

    @Override
    public void log(Throwable t) {
        t.printStackTrace();
    }
}
