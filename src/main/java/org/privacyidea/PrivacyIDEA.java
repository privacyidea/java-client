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
    // Thread pool for connections
    private final BlockingQueue<Runnable> queue = new ArrayBlockingQueue<>(1000);
    private final ThreadPoolExecutor threadPool = new ThreadPoolExecutor(20, 20, 10, TimeUnit.SECONDS, queue);
    final JSONParser parser;
    // Responses from these endpoints will not be logged. The list can be overwritten.
    private List<String> logExcludedEndpoints = Arrays.asList(PIConstants.ENDPOINT_AUTH,
                                                              PIConstants.ENDPOINT_POLLTRANSACTION); //Collections.emptyList(); //

    private PrivacyIDEA(PIConfig configuration, IPILogger logger, IPISimpleLogger simpleLog)
    {
        this.log = logger;
        this.simpleLog = simpleLog;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this);
        this.parser = new JSONParser(this);
        this.threadPool.allowCoreThreadTimeOut(true);
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map)
     */
    public PIResponse validateCheck(String username, String pass)
    {
        return this.validateCheck(username, pass, null, Collections.emptyMap());
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map)
     */
    public PIResponse validateCheck(String username, String pass, Map<String, String> headers)
    {
        return this.validateCheck(username, pass, null, headers);
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String, Map)
     */
    public PIResponse validateCheck(String username, String pass, String transactionID)
    {
        return this.validateCheck(username, pass, transactionID, Collections.emptyMap());
    }

    /**
     * Send a request to validate/check with the given parameters.
     * Which parameters to send depends on the use case and how privacyIDEA is configured.
     * (E.g. this can also be used to trigger challenges without a service account)
     *
     * @param username      username
     * @param pass          pass/otp value
     * @param transactionID optional, will be appended if set
     * @param headers       optional headers for the request
     * @return PIResponse object containing the response or null if error
     */
    public PIResponse validateCheck(String username, String pass, String transactionID, Map<String, String> headers)
    {
        return getPIResponse(USER, username, pass, headers, transactionID);
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass)
    {
        return this.validateCheckSerial(serial, pass, null, Collections.emptyMap());
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass, Map<String, String> headers)
    {
        return this.validateCheckSerial(serial, pass, null, headers);
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String, Map)
     */
    public PIResponse validateCheckSerial(String serial, String pass, String transactionID)
    {
        return this.validateCheckSerial(serial, pass, transactionID, Collections.emptyMap());
    }

    /**
     * Send a request to /validate/check with the serial rather than the username to identify exact token.
     *
     * @param serial        serial of the token
     * @param pass          pass/otp value
     * @param transactionID transaction ID
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckSerial(String serial, String pass, String transactionID, Map<String, String> headers)
    {
        return getPIResponse(SERIAL, serial, pass, headers, transactionID);
    }

    /**
     * Used by validateCheck and validateCheckSerial to get the PI Response.
     *
     * @param type          distinguish between user and serial to set forwarded input to the right PI-request param
     * @param input         forwarded username for classic validateCheck or serial to trigger exact token
     * @param pass          OTP, PIN+OTP or password to use
     * @param headers       optional headers for the request
     * @param transactionID optional, will be appended if set
     * @return PIResponse object containing the response or null if error
     */
    private PIResponse getPIResponse(String type, String input, String pass, Map<String, String> headers, String transactionID)
    {
        Map<String, String> params = new LinkedHashMap<>();
        // Add forwarded user or serial to the params
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
     * @see PrivacyIDEA#validateCheckWebAuthn(String, String, String, String, Map)
     */
    public PIResponse validateCheckWebAuthn(String user, String transactionID, String signResponse, String origin)
    {
        return this.validateCheckWebAuthn(user, transactionID, signResponse, origin, Collections.emptyMap());
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a WebAuthn token.
     *
     * @param user                 username
     * @param transactionID        transaction ID
     * @param webAuthnSignResponse the WebAuthnSignResponse as returned from the browser
     * @param origin               server name that was used for
     * @param headers              optional headers for the request
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckWebAuthn(String user, String transactionID, String webAuthnSignResponse, String origin,
                                            Map<String, String> headers)
    {
        Map<String, String> params = new LinkedHashMap<>();
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
     * @see PrivacyIDEA#triggerChallenges(String, Map)
     */
    public PIResponse triggerChallenges(String username)
    {
        return this.triggerChallenges(username, new LinkedHashMap<>());
    }

    /**
     * Trigger all challenges for the given username. This requires a service account to be set.
     *
     * @param username username to trigger challenges for
     * @param headers  optional headers for the request
     * @return the server response or null if error
     */
    public PIResponse triggerChallenges(String username, Map<String, String> headers)
    {
        Objects.requireNonNull(username, "Username is required!");

        if (!serviceAccountAvailable())
        {
            log("No service account configured. Cannot trigger challenges");
            return null;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        appendRealm(params);

        String response = runRequestAsync(ENDPOINT_TRIGGERCHALLENGE, params, headers, true, POST);
        return this.parser.parsePIResponse(response);
    }

    /**
     * Poll for status of the given transaction ID once.
     *
     * @param transactionID transaction ID to poll for
     * @return the status value, true or false
     */
    public boolean pollTransaction(String transactionID)
    {
        Objects.requireNonNull(transactionID, "TransactionID is required!");

        String
                response =
                runRequestAsync(ENDPOINT_POLLTRANSACTION, Collections.singletonMap(TRANSACTION_ID, transactionID), Collections.emptyMap(),
                                false, GET);
        PIResponse piresponse = this.parser.parsePIResponse(response);
        return piresponse.value;
    }

    /**
     * Get the auth token from the /auth endpoint using the service account.
     *
     * @return auth token or null.
     */
    public String getAuthToken()
    {
        if (!serviceAccountAvailable())
        {
            error("Cannot retrieve auth token without service account!");
            return null;
        }
        String response = runRequestAsync(ENDPOINT_AUTH, serviceAccountParam(), Collections.emptyMap(), false, POST);
        return parser.extractAuthToken(response);
    }

    Map<String, String> serviceAccountParam()
    {
        Map<String, String> authTokenParams = new LinkedHashMap<>();
        authTokenParams.put(USERNAME, configuration.getServiceAccountName());
        authTokenParams.put(PASSWORD, configuration.getServiceAccountPass());

        if (configuration.getServiceAccountRealm() != null && !configuration.getServiceAccountRealm().isEmpty())
        {
            authTokenParams.put(REALM, configuration.getServiceAccountRealm());
        }
        else if (configuration.getRealm() != null && !configuration.getRealm().isEmpty())
        {
            authTokenParams.put(REALM, configuration.getRealm());
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

        String response = runRequestAsync(ENDPOINT_TOKEN, Collections.singletonMap(USER, username), new LinkedHashMap<>(), true, GET);
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

    private void appendRealm(Map<String, String> params)
    {
        if (configuration.getRealm() != null && !configuration.getRealm().isEmpty())
        {
            params.put(REALM, configuration.getRealm());
        }
    }

    /**
     * Run a request in a thread of the thread pool. Then join that thread to the one that was calling this method.
     * If the server takes longer to answer a request, the other requests do not have to wait.
     *
     * @param path              path to the endpoint of the privacyIDEA server
     * @param params            request parameters
     * @param headers           request headers
     * @param authTokenRequired whether an auth token should be acquired prior to the request
     * @param method            http request method
     * @return response of the server as string or null
     */
    private String runRequestAsync(String path, Map<String, String> params, Map<String, String> headers, boolean authTokenRequired,
                                   String method)
    {
        if (!configuration().getForwardClientIP().isEmpty())
        {
            params.put(CLIENT_IP,configuration().getForwardClientIP());
        }
        Callable<String> callable = new AsyncRequestCallable(this, endpoint, path, params, headers, authTokenRequired, method);
        Future<String> future = threadPool.submit(callable);
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
     * @return true if a service account is available
     */
    public boolean serviceAccountAvailable()
    {
        return configuration.getServiceAccountName() != null && !configuration.getServiceAccountName().isEmpty()
               && configuration.getServiceAccountPass() != null &&
               !configuration.getServiceAccountPass().isEmpty();
    }

    PIConfig configuration()
    {
        return configuration;
    }

    /**
     * Pass the message to the appropriate logger implementation.
     *
     * @param message message to log.
     */
    void error(String message)
    {
        if (!configuration.getDisableLog())
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
        if (!configuration.getDisableLog())
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
        if (!configuration.getDisableLog())
        {
            if (this.log != null)
            {
                this.log.log(message);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(message);
            }
            else
            {
                System.out.println(message);
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
        if (!configuration.getDisableLog())
        {
            if (this.log != null)
            {
                this.log.log(e);
            }
            else if (this.simpleLog != null)
            {
                this.simpleLog.piLog(e.getMessage());
            }
            else
            {
                System.out.println(e.getLocalizedMessage());
            }
        }
    }

    @Override
    public void close() throws IOException
    {
        this.threadPool.shutdown();
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

    public static class Builder
    {
        private final String serverURL;
        private final String userAgent;
        private String realm = "";
        private boolean verifySSL = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private String serviceAccountRealm = "";
        private String forwardClientIP = "";
        private IPILogger logger = null;
        private boolean disableLog = false;
        private IPISimpleLogger simpleLogBridge = null;
        private int httpTimeoutMs = 30000;

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
         * Set the client IP to be forwarded to the privacyIDEA server.
         *
         * @param clientIP client IP or an empty String
         * @return Builder
         */
        public Builder forwardClientIP(String clientIP)
        {
            this.forwardClientIP = clientIP;
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

        public PrivacyIDEA build()
        {
            PIConfig configuration = new PIConfig(serverURL, userAgent);
            configuration.setRealm(realm);
            configuration.setVerifySSL(verifySSL);
            configuration.setServiceAccountName(serviceAccountName);
            configuration.setServiceAccountPass(serviceAccountPass);
            configuration.setServiceAccountRealm(serviceAccountRealm);
            configuration.setForwardClientIP(forwardClientIP);
            configuration.setDisableLog(disableLog);
            configuration.setHttpTimeoutMs(httpTimeoutMs);
            return new PrivacyIDEA(configuration, logger, simpleLogBridge);
        }
    }
}