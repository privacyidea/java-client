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

import java.io.Closeable;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

import static org.privacyidea.PIConstants.*;

/**
 * This is the main class. It implements the common endpoints such as /validate/check as methods for easy usage.
 * To create an instance of this class, use the nested PrivacyIDEA.Builder class.
 */
public class PrivacyIDEA implements Closeable
{
    private final PIConfig configuration;
    private final IPILogger log;
    private final IPISimpleLogger simpleLog;
    private final Endpoint endpoint;
    private String jwt = null;
    // Thread pool for connections
    private final BlockingQueue<Runnable> queue = new ArrayBlockingQueue<>(1000);
    private final ThreadPoolExecutor threadPool = new ThreadPoolExecutor(20, 20, 10, TimeUnit.SECONDS, queue);
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private CountDownLatch jwtRetrievalLatch;
    final JSONParser parser;
    // Responses from these endpoints will not be logged. The list can be overwritten.
    private List<String> logExcludedEndpoints = Arrays.asList(
            PIConstants.ENDPOINT_POLLTRANSACTION); //Collections.emptyList();PIConstants.ENDPOINT_AUTH,

    private PrivacyIDEA(PIConfig configuration, IPILogger logger, IPISimpleLogger simpleLog)
    {
        this.log = logger;
        this.simpleLog = simpleLog;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this);
        this.parser = new JSONParser(this);
        this.threadPool.allowCoreThreadTimeOut(true);
        if (serviceAccountAvailable())
        {
            retrieveJWT();
        }
        else
        {
            error("No service account configured. No JWT will be retrieved.");
        }
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map, Map)
     */
    public PIResponse validateCheck(String username, String pass)
    {
        return this.validateCheck(username, pass, null, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map, Map)
     */
    public PIResponse validateCheck(String username, String pass, Map<String, String> headers)
    {
        return this.validateCheck(username, pass, null, Collections.emptyMap(), headers);
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map, Map)
     */
    public PIResponse validateCheck(String username, String pass, String transactionID)
    {
        return this.validateCheck(username, pass, transactionID, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map, Map)
     */
    public PIResponse validateCheck(String username, String pass, String transactionID, Map<String, String> headers)
    {
        return this.validateCheck(username, pass, transactionID, Collections.emptyMap(), headers);
    }

    /**
     * Send a request to validate/check with the given parameters.
     * Which parameters to send depends on the use case and how privacyIDEA is configured.
     * (E.g. this can also be used to trigger challenges without a service account)
     *
     * @param username         username
     * @param pass             pass/otp value
     * @param transactionID    optional, will be appended if set
     * @param additionalParams additional parameters for the request
     * @param headers          optional headers for the request
     * @return PIResponse object containing the response or null if error
     */
    public PIResponse validateCheck(String username, String pass, String transactionID, Map<String, String> additionalParams,
                                    Map<String, String> headers)
    {
        return getPIResponse(USER, username, pass, headers, transactionID, additionalParams);
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass)
    {
        return this.validateCheckSerial(serial, pass, null, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass, Map<String, String> headers)
    {
        return this.validateCheckSerial(serial, pass, null, Collections.emptyMap(), headers);
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass, String transactionID)
    {
        return this.validateCheckSerial(serial, pass, transactionID, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * Send a request to /validate/check with the serial rather than the username to identify exact token.
     *
     * @param serial        serial of the token
     * @param pass          pass/otp value
     * @param transactionID transaction ID
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckSerial(String serial, String pass, String transactionID, Map<String, String> additionalParams,
                                          Map<String, String> headers)
    {
        return getPIResponse(SERIAL, serial, pass, headers, transactionID, additionalParams);
    }

    /**
     * Used by validateCheck and validateCheckSerial to get the PI Response.
     *
     * @param type             distinguish between user and serial to set forwarded input to the right PI-request param
     * @param input            forwarded username for classic validateCheck or serial to trigger exact token
     * @param pass             OTP, PIN+OTP or password to use
     * @param headers          optional headers for the request
     * @param transactionID    optional, will be appended if set
     * @param additionalParams additional parameters for the request
     * @return PIResponse object containing the response or null if error
     */
    private PIResponse getPIResponse(String type, String input, String pass, Map<String, String> headers, String transactionID,
                                     Map<String, String> additionalParams)
    {
        Map<String, String> params = new LinkedHashMap<>(additionalParams);
        params.put(type, input);
        params.put(PASS, (pass != null ? pass : ""));
        appendRealm(params);
        if (transactionID != null && !transactionID.isEmpty())
        {
            params.put(TRANSACTION_ID, transactionID);
        }
        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, headers, false, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * @see PrivacyIDEA#validateCheckWebAuthn(String, String, String, String, Map, Map)
     */
    public PIResponse validateCheckWebAuthn(String user, String transactionID, String signResponse, String origin)
    {
        return this.validateCheckWebAuthn(user, transactionID, signResponse, origin, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a WebAuthn token.
     *
     * @param user                 username
     * @param transactionID        transaction ID
     * @param webAuthnSignResponse the WebAuthnSignResponse as returned from the browser
     * @param origin               server name that was used for
     * @param additionalParams     additional parameters for the request
     * @param headers              optional headers for the request
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckWebAuthn(String user, String transactionID, String webAuthnSignResponse, String origin,
                                            Map<String, String> additionalParams, Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>(additionalParams);
        // Standard validateCheck data
        params.put(USER, user);
        params.put(TRANSACTION_ID, transactionID);
        params.put(PASS, "");
        appendRealm(params);

        // Additional WebAuthn data
        Map<String, String> wanParams = parser.parseWebAuthnSignResponse(webAuthnSignResponse);
        params.putAll(wanParams);

        Map<String, String> hdrs = new LinkedHashMap<>();
        hdrs.put(HEADER_ORIGIN, origin);
        hdrs.putAll(headers);

        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, hdrs, false, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * Request an unbound challenge from the server. Unbound means that any token that has the same type may answer the challenge.
     * In contrast, traditional challenges that were triggered for a user are bound to specific token by their serial.
     * Note: Currently on type "passkey" is supported by privacyIDEA.
     *
     * @param type type of the challenge
     * @return PIResponse or null if error
     */
    public PIResponse validateInitialize(String type)
    {
        Map<String, String> params = new LinkedHashMap<>();
        params.put(TYPE, type);

        String response = runRequestAsync(ENDPOINT_VALIDATE_INITIALIZE, params, Collections.emptyMap(), false, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * Authenticate using a passkey. If successful, the response will contain the username.
     *
     * @param transactionID   transactionID
     * @param passkeyResponse the json serialized response from the authenticator. Is the same as a webauthnSignResponse.
     * @param origin          origin of the passkeyResponse, usually gotten from a browser
     * @param headers         optional headers for the request
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckPasskey(String transactionID, String passkeyResponse, String origin, Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>();
        params.put(TRANSACTION_ID, transactionID);
        params.putAll(parser.parseFIDO2AuthenticationResponse(passkeyResponse));

        Map<String, String> hdrs = new LinkedHashMap<>();
        hdrs.put(HEADER_ORIGIN, origin);
        hdrs.putAll(headers);

        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, hdrs, false, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * Complete a passkey registration via the endpoint /validate/check. This is the second step of the registration process that was
     * triggered by the enroll_via_multichallenge setting in privacyIDEA.
     *
     * @param transactionID        transactionID
     * @param serial               serial of the token
     * @param username             username
     * @param registrationResponse the registration data from the authenticator in json format
     * @param origin               origin of the registrationResponse, usually gotten from a browser
     * @param headers              optional headers for the request
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckCompletePasskeyRegistration(String transactionID, String serial, String username,
                                                               String registrationResponse, String origin, Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>();
        params.put(TRANSACTION_ID, transactionID);
        params.put(SERIAL, serial);
        params.put(USER, username);
        params.put(TYPE, TOKEN_TYPE_PASSKEY);
        params.putAll(parser.parseFIDO2RegistrationResponse(registrationResponse));

        Map<String, String> hdrs = new LinkedHashMap<>();
        hdrs.put(HEADER_ORIGIN, origin);
        hdrs.putAll(headers);

        String response = runRequestAsync(ENDPOINT_VALIDATE_CHECK, params, hdrs, false, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * @see PrivacyIDEA#triggerChallenges(String, Map, Map)
     */
    public PIResponse triggerChallenges(String username)
    {
        return this.triggerChallenges(username, Collections.emptyMap(), Collections.emptyMap());
    }

    /**
     * Trigger all challenges for the given username. This requires a service account to be set.
     *
     * @param username         username to trigger challenges for
     * @param additionalParams additional parameters for the request
     * @param headers          optional headers for the request
     * @return the server response or null if error
     */
    public PIResponse triggerChallenges(String username, Map<String, String> additionalParams, Map<String, String> headers)
    {
        Objects.requireNonNull(username, "Username is required!");
        if (!serviceAccountAvailable())
        {
            log("No service account configured. Cannot trigger challenges");
            return null;
        }
        Map<String, String> headersCopy = new LinkedHashMap<>(headers);
        Map<String, String> params = new LinkedHashMap<>(additionalParams);
        params.put(USER, username);
        appendRealm(params);

        String response = runRequestAsync(ENDPOINT_TRIGGERCHALLENGE, params, headersCopy, true, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * Poll for status of the given transaction ID once.
     *
     * @param transactionID transaction ID to poll for
     * @return the challenge status or "ChallengeStatus.none" if error
     */
    public ChallengeStatus pollTransaction(String transactionID)
    {
        Objects.requireNonNull(transactionID, "TransactionID is required!");

        Map<String, String> params = new LinkedHashMap<>();
        params.put(TRANSACTION_ID, transactionID);
        String response = runRequestAsync(ENDPOINT_POLLTRANSACTION, params, Collections.emptyMap(), false, GET);
        PIResponse piresponse = this.parser.parsePIResponse(response);
        return piresponse.challengeStatus;
    }

    /**
     * Get the service account parameters.
     *
     * @return map with username and password.
     */
    Map<String, String> serviceAccountParam()
    {
        Map<String, String> authTokenParams = new LinkedHashMap<>();
        authTokenParams.put(USERNAME, configuration.serviceAccountName);
        authTokenParams.put(PASSWORD, configuration.serviceAccountPass);

        if (configuration.serviceAccountRealm != null && !configuration.serviceAccountRealm.isEmpty())
        {
            authTokenParams.put(REALM, configuration.serviceAccountRealm);
        }
        else if (configuration.realm != null && !configuration.realm.isEmpty())
        {
            authTokenParams.put(REALM, configuration.realm);
        }
        return authTokenParams;
    }

    /**
     * Retrieve information about the users tokens. This requires a service account to be set.
     *
     * @param username username to get info for
     * @return possibly empty list of TokenInfo or null if failure
     */
    public List<TokenInfo> getTokenInfo(String username)
    {
        Objects.requireNonNull(username);
        if (!serviceAccountAvailable())
        {
            error("Cannot retrieve token info without service account!");
            return null;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        String response = runRequestAsync(ENDPOINT_TOKEN, params, new LinkedHashMap<>(), true, GET);
        return parser.parseTokenInfoList(response);
    }

    /**
     * Enroll a new token of the specified type for the specified user.
     * This requires a service account to be set. Currently, only HOTP and TOTP type token are supported.
     *
     * @param username     username
     * @param typeToEnroll token type to enroll
     * @return RolloutInfo which contains all info for the token or null if error
     */
    public RolloutInfo tokenRollout(String username, String typeToEnroll)
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        params.put(TYPE, typeToEnroll);
        params.put(GENKEY, "1"); // Let the server generate the secret

        String response = runRequestAsync(ENDPOINT_TOKEN_INIT, params, new LinkedHashMap<>(), true, POST);

        return parser.parseRolloutInfo(response);
    }

    /**
     * Init a new token of the specified type for the specified user.
     * This requires a service account to be set. Currently, only HOTP and TOTP type token are supported.
     *
     * @param username     username
     * @param typeToEnroll token type to enroll
     * @param otpKey       secret to import
     * @return RolloutInfo which contains all info for the token or null if error
     */
    public RolloutInfo tokenInit(String username, String typeToEnroll, String otpKey)
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        params.put(TYPE, typeToEnroll);
        params.put(OTPKEY, otpKey); // Import the secret

        String response = runRequestAsync(ENDPOINT_TOKEN_INIT, params, new LinkedHashMap<>(), true, POST);

        return parser.parseRolloutInfo(response);
    }

    /**
     * Append the realm to the parameters if it is set.
     *
     * @param params parameters
     */
    private void appendRealm(Map<String, String> params)
    {
        if (configuration.realm != null && !configuration.realm.isEmpty())
        {
            params.put(REALM, configuration.realm);
        }
    }

    /**
     * Retrieve the JWT from the /auth endpoint and schedule the next retrieval.
     */
    private void retrieveJWT()
    {
        log("Getting new JWT with service account...");
        this.jwtRetrievalLatch = new CountDownLatch(1);
        try
        {
            String response = runRequestAsync(ENDPOINT_AUTH, serviceAccountParam(), Collections.emptyMap(), false, POST);
            if (response == null)
            {
                error("Failed to retrieve JWT: Response was empty. Retrying in 10 seconds.");
                this.scheduler.schedule(this::retrieveJWT, 10, TimeUnit.SECONDS);
            }
            else
            {
                LinkedHashMap<String, String> jwtMap = parser.getJWT(response);
                this.jwt = jwtMap.get(JWT);
                long jwtExpiration = Integer.parseInt(jwtMap.get(JWT_EXPIRATION_TIME));

                // Schedule the next token retrieval to 1 min before expiration
                long delay = Math.max(1, jwtExpiration - 60 - (System.currentTimeMillis() / 1000L));
                this.scheduler.schedule(this::retrieveJWT, delay, TimeUnit.SECONDS);
                log("Next JWT retrieval in " + delay + " seconds.");
            }
        }
        catch (Exception e)
        {
            error("Failed to retrieve JWT: " + e.getMessage());
        }
        this.jwtRetrievalLatch.countDown();
    }

    /**
     * Get the JWT from the /auth endpoint using the service account.
     *
     * @return JWT as string or null on error.
     */
    public String getJWT()
    {
        if (jwtRetrievalLatch.getCount() == 0 && this.jwt == null)
        {
            retrieveJWT();
        }
        try
        {
            jwtRetrievalLatch.await();
        }
        catch (InterruptedException e)
        {
            error("Error while waiting for JWT retrieval: " + e.getMessage());
            error(e);
            return null;
        }
        return this.jwt;
    }

    /**
     * @return true if a service account is available
     */
    public boolean serviceAccountAvailable()
    {
        return configuration.serviceAccountName != null && !configuration.serviceAccountName.isEmpty() &&
               configuration.serviceAccountPass != null && !configuration.serviceAccountPass.isEmpty();
    }

    /**
     * Run a request in a thread of the thread pool. Then join that thread to the one that was calling this method.
     * If the server takes longer to answer a request, the other requests do not have to wait.
     *
     * @param path                  path to the endpoint of the privacyIDEA server
     * @param params                request parameters
     * @param headers               request headers
     * @param authorizationRequired whether an JWT for Authorization should be acquired prior to the request. Requires a service account.
     * @param method                http request method
     * @return response of the server as string or null
     */
    private String runRequestAsync(String path, Map<String, String> params, Map<String, String> headers, boolean authorizationRequired,
                                   String method)
    {
        if (authorizationRequired)
        {
            // Wait for the JWT to be retrieved and add it to the header
            headers.put(PIConstants.HEADER_AUTHORIZATION, getJWT());
        }
        Callable<String> callable = new AsyncRequestCallable(this, this.endpoint, path, params, headers, method);
        Future<String> future = this.threadPool.submit(callable);
        String response = null;
        try
        {
            response = future.get();
        }
        catch (InterruptedException | ExecutionException e)
        {
            log("runRequestAsync: " + e.getLocalizedMessage());
        }
        return response;
    }

    /**
     * @return the configuration of this instance
     */
    PIConfig configuration()
    {
        return configuration;
    }

    /**
     * @return list of endpoints for which the response is not printed
     */
    public List<String> logExcludedEndpoints()
    {
        return this.logExcludedEndpoints;
    }

    /**
     * @param list list of endpoints for which the response should not be printed
     */
    public void logExcludedEndpoints(List<String> list)
    {
        this.logExcludedEndpoints = list;
    }

    /**
     * Pass the message to the appropriate logger implementation.
     *
     * @param message message to log.
     */
    void error(String message)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.error(message);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(message);
            }
            else
            {
                System.err.println(message);
            }
        }
    }

    /**
     * Pass the error to the appropriate logger implementation.
     *
     * @param e error to log.
     */
    void error(Throwable e)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.error(e);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(e.getMessage());
            }
            else
            {
                System.err.println(e.getLocalizedMessage());
            }
        }
    }

    /**
     * Pass the message to the appropriate logger implementation.
     *
     * @param message message to log.
     */
    void log(String message)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.log(message);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(message);
            }
        }
    }

    /**
     * Pass the error to the appropriate logger implementation.
     *
     * @param e error to log.
     */
    void log(Throwable e)
    {
        if (!configuration.disableLog)
        {
            if (this.log != null)
            {
                this.log.log(e);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(e.getMessage());
            }
        }
    }

    @Override
    public void close() throws IOException
    {
        this.threadPool.shutdown();
        this.scheduler.shutdownNow();
    }

    /**
     * Get a new Builder to create a PrivacyIDEA instance.
     *
     * @param serverURL url of the privacyIDEA server.
     * @param userAgent userAgent of the plugin using the java-client.
     * @return Builder
     */
    public static Builder newBuilder(String serverURL, String userAgent)
    {
        return new Builder(serverURL, userAgent);
    }

    /**
     * Builder class to create a PrivacyIDEA instance.
     */
    public static class Builder
    {
        private final String serverURL;
        private final String userAgent;
        private String realm = "";
        private boolean verifySSL = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private String serviceAccountRealm = "";
        private IPILogger logger = null;
        private boolean disableLog = false;
        private IPISimpleLogger simpleLogBridge = null;
        private int httpTimeoutMs = 10000;
        private String proxyHost = "";
        private int proxyPort = 0;

        /**
         * @param serverURL the server URL is mandatory to communicate with privacyIDEA.
         * @param userAgent the user agent that should be used in the http requests. Should refer to the plugin, something like "privacyIDEA-Keycloak"
         */
        private Builder(String serverURL, String userAgent)
        {
            this.userAgent = userAgent;
            this.serverURL = serverURL;
        }

        /**
         * Set a logger, which will receive log and error/throwable messages to be passed to the plugins log/error output.
         * This implementation takes precedence over the IPISimpleLogger if both are set.
         *
         * @param logger ILoggerBridge implementation
         * @return Builder
         */
        public Builder logger(IPILogger logger)
        {
            this.logger = logger;
            return this;
        }

        /**
         * Set a simpler logger implementation, which logs all messages as Strings.
         * The IPILogger takes precedence over this if both are set.
         *
         * @param simpleLog IPISimpleLogger implementation
         * @return Builder
         */
        public Builder simpleLogger(IPISimpleLogger simpleLog)
        {
            this.simpleLogBridge = simpleLog;
            return this;
        }

        /**
         * Set a realm that is appended to every request
         *
         * @param realm realm
         * @return Builder
         */
        public Builder realm(String realm)
        {
            this.realm = realm;
            return this;
        }

        /**
         * Set whether to verify the peer when connecting.
         * It is not recommended to set this to false in productive environments.
         *
         * @param verifySSL boolean
         * @return Builder
         */
        public Builder verifySSL(boolean verifySSL)
        {
            this.verifySSL = verifySSL;
            return this;
        }

        /**
         * Set a service account, which can be used to trigger challenges etc.
         *
         * @param serviceAccountName account name
         * @param serviceAccountPass account password
         * @return Builder
         */
        public Builder serviceAccount(String serviceAccountName, String serviceAccountPass)
        {
            this.serviceAccountName = serviceAccountName;
            this.serviceAccountPass = serviceAccountPass;
            return this;
        }

        /**
         * Set the realm for the service account if the account is found in a separate realm from the realm set in {@link Builder#realm(String)}.
         *
         * @param serviceAccountRealm realm of the service account
         * @return Builder
         */
        public Builder serviceRealm(String serviceAccountRealm)
        {
            this.serviceAccountRealm = serviceAccountRealm;
            return this;
        }

        /**
         * Disable logging completely regardless of any set loggers.
         *
         * @return Builder
         */
        public Builder disableLog()
        {
            this.disableLog = true;
            return this;
        }

        /**
         * Set the timeout for http requests in milliseconds.
         *
         * @param httpTimeoutMs timeout in milliseconds
         * @return Builder
         */
        public Builder httpTimeoutMs(int httpTimeoutMs)
        {
            this.httpTimeoutMs = httpTimeoutMs;
            return this;
        }

        /**
         * Set the proxy for the http requests.
         *
         * @param proxyHost proxy host
         * @param proxyPort proxy port
         * @return Builder
         */
        public Builder proxy(String proxyHost, int proxyPort)
        {
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
            return this;
        }

        /**
         * Build the PrivacyIDEA instance with the set parameters.
         * If a service account is set, the JWT retrieval is done immediately.
         *
         * @return PrivacyIDEA instance
         */
        public PrivacyIDEA build()
        {
            PIConfig configuration = new PIConfig(serverURL, userAgent);
            configuration.realm = realm;
            configuration.verifySSL = verifySSL;
            configuration.serviceAccountName = serviceAccountName;
            configuration.serviceAccountPass = serviceAccountPass;
            configuration.serviceAccountRealm = serviceAccountRealm;
            configuration.disableLog = disableLog;
            configuration.httpTimeoutMs = httpTimeoutMs;
            configuration.setProxy(proxyHost, proxyPort);
            return new PrivacyIDEA(configuration, logger, simpleLogBridge);
        }
    }
}