package org.privacyidea;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
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

import static org.junit.Assert.assertNotNull;

public class TestJWT extends PILogImplementation implements org.mockserver.mock.action.ExpectationResponseCallback
{
    private ClientAndServer mockServer;

    // Token validity. The client schedules its refresh 60s before expiry, so a validity of 62s makes it refresh
    // roughly every 2s during the test - exercising several background refreshes.
    private final int jwtValidityMs = 62_000;
    private final int mockServerResponseDelayMs = 1000;
    // Deliberately NOT a multiple of the ~2s refresh cadence, so the reads in the loop are decoupled from the
    // background refresh boundary instead of aliasing with it.
    private final int loopSleepMs = 3000;
    private final int testIterations = 4;

    private final String issuer = "testIssuer";
    private final String subject = "testUser";
    private final String secret = "testSecret";

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

    /**
     * Across several background refresh cycles, getJWT() must always hand out a usable token. Rather than comparing
     * against a field mutated by the mock-server callback thread (which races with the asynchronous refresh), this
     * verifies the actual contract: the returned token is non-null and a valid, non-expired JWT with the expected
     * issuer/subject (signature + expiry checked by the verifier).
     */
    @Test
    public void testMultipleRetrieval()
    {
        for (int i = 0; i < this.testIterations; i++)
        {
            String newJWT = privacyIDEA.getJWT();
            assertNotNull("getJWT() returned null", newJWT);
            // Throws if the token is malformed, expired, wrongly signed or has unexpected claims.
            DecodedJWT decoded = JWT.require(Algorithm.HMAC256(this.secret))
                                    .withIssuer(this.issuer)
                                    .withSubject(this.subject)
                                    .build()
                                    .verify(newJWT);
            assertNotNull(decoded.getExpiresAt());

            try
            {
                Thread.sleep(this.loopSleepMs);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
    }

    @After
    public void tearDown() throws IOException
    {
        // Close the client first so its refresh scheduler is stopped before the mock server goes away; otherwise a
        // scheduled refresh could fire against a dead (or, in the shared-port suite, a foreign) endpoint.
        privacyIDEA.close();
        mockServer.stop();
    }

    private String generateJWT(long validityMs)
    {
        return JWT.create()
                  .withSubject(this.subject)
                  .withIssuer(this.issuer)
                  .withExpiresAt(new Date(System.currentTimeMillis() + validityMs))
                  .sign(Algorithm.HMAC256(this.secret));
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
        // Issue a fresh token on every /auth call. No shared field: the test verifies the token the client returns,
        // not a value mutated here by the mock-server thread.
        String freshJwt = generateJWT(this.jwtValidityMs);
        return HttpResponse.response().withBody(postAuthSuccessResponse(freshJwt));
    }
}
