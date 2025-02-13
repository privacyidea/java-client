package org.privacyidea;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Delay;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.util.Date;

import static org.junit.Assert.assertEquals;

public class TestJWT extends PILogImplementation implements org.mockserver.mock.action.ExpectationResponseCallback
{
    private ClientAndServer mockServer;
    private String jwt;
    private int jwtExpirationTimeMs = 3000;
    private int mockServerResponseDelayMs = 2000;
    private int testIterations = 3;

    private final String serviceAccount = "admin";
    private final String servicePassword = "admin";
    private PrivacyIDEA privacyIDEA;


    @Before
    public void setup()
    {
        this.mockServer = ClientAndServer.startClientAndServer(1080);
        this.mockServer.when(HttpRequest.request()
                                        .withPath(PIConstants.ENDPOINT_AUTH)
                                        .withMethod("POST")
                                        .withBody("username=" + serviceAccount + "&password=" + servicePassword))
                       .respond(this, new Delay(TimeUnit.MILLISECONDS, this.mockServerResponseDelayMs));
        // When build() is called with a service account set, a jwt retrieval is attempted immediately, therefore, the mock server has to
        // be ready
        this.privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                      .serviceAccount(this.serviceAccount, this.servicePassword)
                                      .httpTimeoutMs(15000)
                                      //.logger(this)
                                      .verifySSL(false)
                                      .build();
    }

    @Test
    public void testMultipleRetrieval()
    {
        for (int i = 0; i < this.testIterations; i++)
        {
            assertEquals(this.jwt, privacyIDEA.getJWT());
            try
            {
                Thread.sleep(this.jwtExpirationTimeMs);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
        // Wait for the last connection to finish before closing
        try
        {
            Thread.sleep(this.mockServerResponseDelayMs);
        }
        catch (InterruptedException e)
        {
            throw new RuntimeException(e);
        }
    }

    @After
    public void tearDown() throws IOException
    {
        mockServer.stop();
        privacyIDEA.close();
    }

    private String generateJWT(long validityMs)
    {
        //log("JWT expiration date: " + new Date(System.currentTimeMillis() + validityMs));
        return JWT.create()
                  .withSubject("testUser")
                  .withIssuer("testIssuer")
                  .withExpiresAt(new Date(System.currentTimeMillis() + validityMs))
                  .sign(Algorithm.HMAC256("testSecret"));
    }

    private String postAuthSuccessResponse(String jwt)
    {
        return "{\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" + "    \"result\": {\n" + "        \"status\": true,\n" +
               "        \"value\": {\n" + "            \"log_level\": 20,\n" + "            \"menus\": [\n" +
               "                \"components\",\n" + "                \"machines\"\n" + "            ],\n" +
               "            \"realm\": \"\",\n" + "            \"rights\": [\n" + "                \"policydelete\",\n" +
               "                \"resync\"\n" + "            ],\n" + "            \"role\": \"admin\",\n" + "            \"token\": \"" +
               jwt + "\",\n" + "            \"username\": \"admin\",\n" + "            \"logout_time\": 120,\n" +
               "            \"default_tokentype\": \"hotp\",\n" + "            \"user_details\": false,\n" +
               "            \"subscription_status\": 0\n" + "        }\n" + "    },\n" + "    \"time\": " +
               (System.currentTimeMillis() / 1000L) + ",\n" + "    \"version\": \"privacyIDEA 3.2.1\",\n" +
               "    \"versionnumber\": \"3.2.1\",\n" + "    \"signature\": \"rsa_sha256_pss:\"\n" + "}";
    }

    @Override
    public HttpResponse handle(HttpRequest httpRequest) throws Exception
    {
        // The next retrieval is always scheduled for 1 minute before expiration
        this.jwt = generateJWT(60000 + this.jwtExpirationTimeMs);
        return HttpResponse.response().withBody(postAuthSuccessResponse(this.jwt));
    }
}