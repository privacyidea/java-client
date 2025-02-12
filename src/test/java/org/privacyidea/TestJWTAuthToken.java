package org.privacyidea;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.util.Date;

import static org.junit.Assert.assertEquals;

public class TestJWTAuthToken
{
    private ClientAndServer mockServer;
    private String authToken;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    /**
     * Test if the JWT auth token is updated after the expiration time.
     */
    @Test
    public void testSuccess()
    {
        String serviceAccount = "admin";
        String servicePassword = "admin";

        // Pre-set the auth token
        authToken = getAuthToken();

        mockServer.when(HttpRequest.request()
                                   .withPath(PIConstants.ENDPOINT_AUTH)
                                   .withMethod("POST")
                                   .withBody("username=" + serviceAccount + "&password=" + servicePassword))
                  .respond(HttpResponse.response()
                                       .withBody(postAuthSuccessResponse()));

        PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                             .serviceAccount(serviceAccount, servicePassword)
                                             .httpTimeoutMs(15000)
                                             .verifySSL(false)
                                             .logger(new PILogImplementation())
                                             .simpleLogger(System.out::println)
                                             .build();

        // Check if the auth token is updated after expiration time
        for (int i = 0; i < 2; i++)
        {
            // Compare the tokens
            assertEquals(authToken, privacyIDEA.authToken);

            System.out.println("Expected: " + authToken);
            System.out.println("Actual  : " + privacyIDEA.authToken);
            System.out.println(i + 1 + "/3 auth token test passed!");

            // Actualize the auth token
            authToken = getAuthToken();

            // Reset the mock server response
            mockServer.clear(HttpRequest.request()
                                        .withPath(PIConstants.ENDPOINT_AUTH)
                                        .withMethod("POST")
                                        .withBody("username=" + serviceAccount + "&password=" + servicePassword));

            mockServer.when(HttpRequest.request()
                                       .withPath(PIConstants.ENDPOINT_AUTH)
                                       .withMethod("POST")
                                       .withBody("username=" + serviceAccount + "&password=" + servicePassword))
                      .respond(HttpResponse.response()
                                           .withBody(postAuthSuccessResponse()));

            // Wait 5 seconds for a new token
            try
            {
                Thread.sleep(3000);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }

        assertEquals(authToken, privacyIDEA.authToken);
        System.out.println("Expected: " + authToken);
        System.out.println("Actual  : " + privacyIDEA.authToken);
        System.out.println("3/3 auth token test passed!");
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }

    /**
     * Create the auth tokens substitute.
     * This method is not used in the test, but it is used in the main code.
     *
     * @return String - the auth token
     */
    private String getAuthToken()
    {
        System.out.println("JWT test token's expiration date: " + new Date(System.currentTimeMillis() + 65000));
        return JWT.create()
                  .withSubject("testUser")
                  .withIssuer("testIssuer")
                  .withExpiresAt(new Date(System.currentTimeMillis() + 65000))
                  .sign(Algorithm.HMAC256("testSecret"));
    }

    private String postAuthSuccessResponse()
    {
        return "{\n" + "    \"id\": 1,\n" +
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
               "            \"token\": \"" +
               authToken + "\",\n" +
               "            \"username\": \"admin\",\n" +
               "            \"logout_time\": 120,\n" +
               "            \"default_tokentype\": \"hotp\",\n" +
               "            \"user_details\": false,\n" +
               "            \"subscription_status\": 0\n" +
               "        }\n" + "    },\n" +
               "    \"time\": " + (System.currentTimeMillis() / 1000L) + ",\n" +
               "    \"version\": \"privacyIDEA 3.2.1\",\n" +
               "    \"versionnumber\": \"3.2.1\",\n" +
               "    \"signature\": \"rsa_sha256_pss:\"\n" +
               "}";
    }
}
