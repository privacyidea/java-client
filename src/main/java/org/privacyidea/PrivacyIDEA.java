/*
 * Copyright 2021 NetKnights GmbH - nils.behlen@netknights.it
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.privacyidea.PIConstants.ASSERTIONCLIENTEXTENSIONS;
import static org.privacyidea.PIConstants.AUTHENTICATORDATA;
import static org.privacyidea.PIConstants.CLIENTDATA;
import static org.privacyidea.PIConstants.CREDENTIALID;
import static org.privacyidea.PIConstants.ENDPOINT_POLLTRANSACTION;
import static org.privacyidea.PIConstants.ENDPOINT_TOKEN;
import static org.privacyidea.PIConstants.ENDPOINT_TOKEN_INIT;
import static org.privacyidea.PIConstants.ENDPOINT_TRIGGERCHALLENGE;
import static org.privacyidea.PIConstants.ENDPOINT_VALIDATE_CHECK;
import static org.privacyidea.PIConstants.GENKEY;
import static org.privacyidea.PIConstants.GET;
import static org.privacyidea.PIConstants.HEADER_ORIGIN;
import static org.privacyidea.PIConstants.PASS;
import static org.privacyidea.PIConstants.POST;
import static org.privacyidea.PIConstants.REALM;
import static org.privacyidea.PIConstants.RESULT;
import static org.privacyidea.PIConstants.SERIAL;
import static org.privacyidea.PIConstants.SIGNATUREDATA;
import static org.privacyidea.PIConstants.TOKENS;
import static org.privacyidea.PIConstants.TRANSACTION_ID;
import static org.privacyidea.PIConstants.TYPE;
import static org.privacyidea.PIConstants.USER;
import static org.privacyidea.PIConstants.USERHANDLE;
import static org.privacyidea.PIConstants.VALUE;
import static org.privacyidea.PIResponse.getString;

/**
 * This is the main class. It implements the common endpoints such as /validate/check as methods for easy usage.
 * To create an instance of this class, use the nested PrivacyIDEA.Builder class.
 */
public class PrivacyIDEA {

    private final PIConfig configuration;
    private final IPILogger log;
    private final IPISimpleLogger simpleLog;
    private final AtomicBoolean runPoll = new AtomicBoolean(true);
    private final Endpoint endpoint;

    private PrivacyIDEA(PIConfig configuration, IPILogger logger, IPISimpleLogger simpleLog) {
        this.log = logger;
        this.simpleLog = simpleLog;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this);
    }

    /**
     * @see PrivacyIDEA#validateCheck(String, String, String)
     */
    public PIResponse validateCheck(String username, String otp) {
        return validateCheck(username, otp, null);
    }

    /**
     * Send a request to validate/check with the given parameters.
     * Which parameters to send depends on the use case and how privacyIDEA is configured.
     * (E.g. this can also be used to trigger challenges without a service account)
     *
     * @param username      username
     * @param otp           the OTP, PIN+OTP or password to use.
     * @param transactionId optional, will be appended if set
     * @return PIResponse object containing the response or null if error
     */
    public PIResponse validateCheck(String username, String otp, String transactionId) {
        Map<String, String> params = new LinkedHashMap<>();

        params.put(USER, username);
        params.put(PASS, (otp != null ? otp : ""));

        if (transactionId != null && !transactionId.isEmpty()) {
            params.put(TRANSACTION_ID, transactionId);
        }

        appendRealm(params);

        String response = endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
        return checkServerResponse(response);
    }

    /**
     * @see PrivacyIDEA#validateCheckSerial(String, String, String)
     */
    public PIResponse validateCheckSerial(String serial, String otp) {
        return validateCheckSerial(serial, otp, null);
    }

    /**
     * Send a request to /validate/check with the serial rather than the username to identify the token.
     *
     * @param serial        serial of the token
     * @param otp           otp value
     * @param transactionId transactionId
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckSerial(String serial, String otp, String transactionId) {
        Map<String, String> params = new LinkedHashMap<>();

        params.put(SERIAL, serial);
        params.put(PASS, (otp != null ? otp : ""));

        if (transactionId != null && transactionId.isEmpty()) {
            params.put(TRANSACTION_ID, transactionId);
        }

        appendRealm(params);

        String response = endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
        return checkServerResponse(response);
    }

    /**
     * Sends a request to /validate/check with the data required to authenticate a WebAuthn token.
     *
     * @param user          username
     * @param transactionId transactionId
     * @param signResponse  the WebAuthnSignResponse as returned from the
     * @param origin        server name that was used for
     * @return PIResponse or null if error
     */
    public PIResponse validateCheckWebAuthn(String user, String transactionId, String signResponse, String origin) {
        Map<String, String> params = new LinkedHashMap<>();

        params.put(USER, user);
        params.put(TRANSACTION_ID, transactionId);
        params.put(PASS, "");

        JsonObject obj;
        try {
            obj = JsonParser.parseString(signResponse).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            error(e);
            return null;
        }

        params.put(CREDENTIALID, getString(obj, CREDENTIALID));
        params.put(CLIENTDATA, getString(obj, CLIENTDATA));
        params.put(SIGNATUREDATA, getString(obj, SIGNATUREDATA));
        params.put(AUTHENTICATORDATA, getString(obj, AUTHENTICATORDATA));

        // The userhandle and assertionclientextension fields are optional
        String userhandle = getString(obj, USERHANDLE);
        if (!userhandle.isEmpty()) {
            params.put(USERHANDLE, userhandle);
        }
        String extensions = getString(obj, ASSERTIONCLIENTEXTENSIONS);
        if (!extensions.isEmpty()) {
            params.put(ASSERTIONCLIENTEXTENSIONS, extensions);
        }

        appendRealm(params);
        String response = endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, Collections.singletonMap(HEADER_ORIGIN, origin), false, POST);
        return checkServerResponse(response);
    }

    /**
     * Trigger all challenges for the given username. This requires a service account to be set.
     *
     * @param username username to trigger challenges for
     * @return the server response or null if error
     */
    public PIResponse triggerChallenges(String username) {
        Objects.requireNonNull(username, "Username is required!");

        if (!checkServiceAccountAvailable()) {
            log("No service account configured. Cannot trigger challenges");
            return null;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);

        appendRealm(params);
        String response = endpoint.sendRequest(ENDPOINT_TRIGGERCHALLENGE, params, true, POST);
        return checkServerResponse(response);
    }

    /**
     * Poll for status of the given transaction ID once.
     *
     * @param transactionId transaction ID to poll for
     * @return the status value, true or false
     */
    public boolean pollTransaction(String transactionId) {
        Objects.requireNonNull(transactionId, "TransactionID is required!");

        // suppress passing the error out of this function but it will still be logged
        PIResponse response = new PIResponse(endpoint.sendRequest(ENDPOINT_POLLTRANSACTION,
                Collections.singletonMap(TRANSACTION_ID, transactionId),
                false, GET));

        return response.getValue();
    }

    /**
     * Poll for the transaction in another thread. Once the polling returns success, the authentication is finalized
     * using validate/check. The given callback is invoked with the result of the finalization.
     * The poll loop is stopped when polling returns success.
     *
     * @param transactionId id of the transaction to poll for
     * @param username      username, required for finalization
     * @param callback      callback to invoke with finalization result
     */
    public void asyncPollTransaction(String transactionId, String username, PIPollTransactionCallback callback) {
        Objects.requireNonNull(transactionId, "TransactionID is required!");
        Objects.requireNonNull(username, "Username is required!");
        Objects.requireNonNull(callback, "Callback is required!");

        runPoll.set(true);
        Thread t = new Thread(() -> {
            int count = 0;
            while (runPoll.get()) {
                // Get the current sleep interval from config, if max use the last value repeatedly
                if (count == configuration.pollingIntervals.size())
                    count--;
                int msToSleep = configuration.pollingIntervals.get(count) * 1000;
                count++;
                try {
                    Thread.sleep(msToSleep);
                } catch (InterruptedException e) {
                    log(e);
                }
                if (pollTransaction(transactionId)) {
                    runPoll.set(false);
                    PIResponse response = validateCheck(username, "", transactionId);
                    callback.transactionFinalized(response);
                    break;
                }
            }
        });
        t.start();
    }

    /**
     * Get the Authorization token for the service account.
     *
     * @return the AuthToken or empty string if error
     */
    public String getAuthToken() {
        if (!checkServiceAccountAvailable()) {
            log("Cannot retrieve auth token without service account!");
            return null;
        }
        return endpoint.getAuthTokenFromServer();
    }

    /**
     * Retrieve information about the users tokens. This requires a service account to be set.
     *
     * @param username username to get info for
     * @return possibly empty list of TokenInfo or null if failure
     */
    public List<TokenInfo> getTokenInfo(String username) {
        Objects.requireNonNull(username);
        if (!checkServiceAccountAvailable()) {
            error("Cannot retrieve token info without service account!");
            return null;
        }

        List<TokenInfo> ret = new ArrayList<>();

        String response = endpoint.sendRequest(ENDPOINT_TOKEN, Collections.singletonMap(USER, username), true, GET);

        if (response == null || response.isEmpty()) {
            return null;
        }

        JsonObject object;
        try {
            object = JsonParser.parseString(response).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            error(e);
            return null;
        }

        JsonObject result = object.getAsJsonObject(RESULT);
        if (result != null) {
            JsonObject value = result.getAsJsonObject(VALUE);
            if (value != null) {
                JsonArray tokens = value.getAsJsonArray(TOKENS);
                if (tokens != null) {
                    List<TokenInfo> infos = new ArrayList<>();
                    tokens.forEach(jsonValue -> infos.add(new TokenInfo(jsonValue.toString())));
                    ret = infos;
                }
            }
        }

        return ret;
    }

    /**
     * Enroll a new token of the specified type for the specified user.
     * This requires a service account to be set. Currently, only HOTP and TOTP type token are supported.
     *
     * @param username     username
     * @param typeToEnroll token type to enroll
     * @return RolloutInfo which contains all info for the token or null if error
     */
    public RolloutInfo tokenRollout(String username, String typeToEnroll) {
        if (!checkServiceAccountAvailable()) {
            error("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USER, username);
        params.put(TYPE, typeToEnroll);
        params.put(GENKEY, "1"); // Let the server generate the secret

        String response = endpoint.sendRequest(ENDPOINT_TOKEN_INIT, params, true, POST);
        if (response == null || response.isEmpty()) {
            return null;
        }
        return new RolloutInfo(response);
    }

    private void appendRealm(Map<String, String> params) {
        if (configuration.realm != null && !configuration.realm.isEmpty()) {
            params.put(REALM, configuration.realm);
        }
    }

    /**
     * Encapsulate how to handle missing server responses here.
     *
     * @param response raw response from endpoint
     * @return PIResponse or null if response null/empty
     */
    private PIResponse checkServerResponse(String response) {
        if (response == null || response.isEmpty()) {
            return null;
        }
        return new PIResponse(response);
    }

    /*
     * Stop the poll loop.
     */
    public void stopPolling() {
        runPoll.set(false);
    }

    /**
     * @return list of endpoints for which the response is not printed
     */
    public List<String> getLogExcludedEndpoints() {
        return endpoint.getLogExcludedEndpoints();
    }

    /**
     * @param list list of endpoints for which the response should not be printed
     */
    public void setLogExcludedEndpoints(List<String> list) {
        endpoint.setLogExcludedEndpoints(list);
    }

    public boolean checkServiceAccountAvailable() {
        return configuration.serviceAccountName != null && !configuration.serviceAccountName.isEmpty()
                && configuration.serviceAccountPass != null && !configuration.serviceAccountPass.isEmpty();
    }

    PIConfig getConfiguration() {
        return configuration;
    }

    void error(String message) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.error(message);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(message);
            } else {
                System.err.println(message);
            }
        }
    }

    void error(Throwable e) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.error(e);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(e.getMessage());
            } else {
                System.err.println(e.getLocalizedMessage());
            }
        }
    }

    void log(String message) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.log(message);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(message);
            } else {
                System.out.println(message);
            }
        }
    }

    void log(Throwable e) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.log(e);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(e.getMessage());
            } else {
                System.out.println(e.getLocalizedMessage());
            }
        }
    }

    public static class Builder {
        private String serverURL = "";
        private String realm = "";
        private boolean doSSLVerify = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private String serviceAccountRealm = "";
        private String userAgent = "";
        private List<Integer> pollingIntervals = Collections.singletonList(1);
        private IPILogger logger = null;
        private boolean disableLog = false;
        private IPISimpleLogger simpleLogBridge = null;

        /**
         * @param serverURL the server URL is mandatory to communicate with privacyIDEA.
         * @param userAgent the user agent that should be used in the http requests. Should refer to the plugin, something like "privacyIDEA-Keycloak"
         */
        public Builder(String serverURL, String userAgent) {
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
        public Builder setLogger(IPILogger logger) {
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
        public Builder setSimpleLogger(IPISimpleLogger simpleLog) {
            this.simpleLogBridge = simpleLog;
            return this;
        }

        /**
         * Set a realm that is appended to every request
         *
         * @param realm realm
         * @return Builder
         */
        public Builder setRealm(String realm) {
            this.realm = realm;
            return this;
        }

        /**
         * Set whether to verify the peer when connecting.
         * It is not recommended to set this to false in productive environments.
         *
         * @param doSSLVerify boolean
         * @return Builder
         */
        public Builder setSSLVerify(boolean doSSLVerify) {
            this.doSSLVerify = doSSLVerify;
            return this;
        }

        /**
         * Set a service account, which can be used to trigger challenges etc.
         *
         * @param serviceAccountName account name
         * @param serviceAccountPass account password
         * @return Builder
         */
        public Builder setServiceAccount(String serviceAccountName, String serviceAccountPass) {
            this.serviceAccountName = serviceAccountName;
            this.serviceAccountPass = serviceAccountPass;
            return this;
        }

        /**
         * Set the realm for the service account if the account is found in a separate realm from the realm set in {@link Builder#setRealm(String)}.
         *
         * @param serviceAccountRealm realm of the service account
         * @return Builder
         */
        public Builder setServiceAccountRealm(String serviceAccountRealm) {
            this.serviceAccountRealm = serviceAccountRealm;
            return this;
        }

        /**
         * Set the intervals at which the polling is done when using asyncPollTransaction.
         * The last number will be repeated if the end of the list is reached.
         *
         * @param intervals list of integers that represent seconds
         * @return Builder
         */
        public Builder setPollingIntervals(List<Integer> intervals) {
            this.pollingIntervals = intervals;
            return this;
        }

        /**
         * Disable logging completely regardless of any set loggers.
         *
         * @return Builder
         */
        public Builder disableLog() {
            this.disableLog = true;
            return this;
        }

        public PrivacyIDEA build() {
            PIConfig configuration = new PIConfig(serverURL, userAgent);
            configuration.realm = realm;
            configuration.doSSLVerify = doSSLVerify;
            configuration.serviceAccountName = serviceAccountName;
            configuration.serviceAccountPass = serviceAccountPass;
            configuration.serviceAccountRealm = serviceAccountRealm;
            configuration.pollingIntervals = pollingIntervals;
            configuration.disableLog = disableLog;
            return new PrivacyIDEA(configuration, logger, simpleLogBridge);
        }
    }
}
