package org.privacyidea;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PrivacyIDEA {

    private final Configuration configuration;
    private final PILoggerBridge log;
    private final PISimpleLogBridge simpleLog;
    private final AtomicBoolean runPoll = new AtomicBoolean(true);
    private final Endpoint endpoint;

    private PrivacyIDEA(Configuration configuration, PILoggerBridge logger, PISimpleLogBridge simpleLog) {
        this.log = logger;
        this.simpleLog = simpleLog;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this, configuration);
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
     * @param username       username
     * @param otp            the OTP, PIN+OTP or password to use.
     * @param transaction_id optional, will be appended if set
     * @return org.privacyidea.PIResponse object containing the response
     */
    public PIResponse validateCheck(String username, String otp, String transaction_id) {
        Map<String, String> params = new LinkedHashMap<>();

        params.put(Constants.PARAM_KEY_USER, username);
        params.put(Constants.PARAM_KEY_PASS, (otp != null ? otp : ""));

        if (transaction_id != null && !transaction_id.isEmpty()) {
            params.put(Constants.PARAM_KEY_TRANSACTION_ID, transaction_id);
        }

        appendRealm(params);

        String response = endpoint.sendRequest(Constants.ENDPOINT_VALIDATE_CHECK, params, false, "POST");

        // TODO return null object or null upon error or empty response
        if (response == null || response.isEmpty()) {
            return null;
        }

        return new PIResponse(response);
    }

    public PIResponse validateCheckSerial(String serial, String otp) {
        Map<String, String> params = new LinkedHashMap<>();

        params.put(Constants.PARAM_KEY_SERIAL, serial);
        params.put(Constants.PARAM_KEY_PASS, (otp != null ? otp : ""));

        appendRealm(params);

        String response = endpoint.sendRequest(Constants.ENDPOINT_VALIDATE_CHECK, params, false, "POST");

        // TODO return null object or null upon error or empty response
        if (response == null || response.isEmpty()) {
            return null;
        }

        return new PIResponse(response);
    }

    private void appendRealm(Map<String, String> params) {
        if (configuration.realm != null && !configuration.realm.isEmpty()) {
            params.put(Constants.PARAM_KEY_REALM, configuration.realm);
        }
    }

    /**
     * Trigger all possible challenges for the given username using a service account
     *
     * @param username username to trigger challenges for
     * @return the server response or null if error
     */
    public PIResponse triggerChallenges(String username) {
        Objects.requireNonNull(username, "Username is required!");

        if (!checkServiceAccountAvailable()) {
            logError("No service account configured. Cannot trigger challenges");
            return null;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put(Constants.PARAM_KEY_USER, username);

        appendRealm(params);

        return new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_TRIGGERCHALLENGE,
                params, true, "POST"));
    }

    /**
     * Poll for status of the given transaction ID once.
     *
     * @param transaction_id transaction ID to poll for
     * @return the status value, true or false
     */
    public boolean pollTransaction(String transaction_id) {
        Objects.requireNonNull(transaction_id, "TransactionID is required!");

        PIResponse response = new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_POLL_TRANSACTION,
                Collections.singletonMap(Constants.PARAM_KEY_TRANSACTION_ID, transaction_id),
                false, "GET"));

        return response.getValue();
    }

    /**
     * Poll for the transaction in another thread. Once the polling returns success, the authentication is finalized
     * using validate/check. The given callback is invoked with the result of the finalization.
     * The poll loop is stopped when polling returns success.
     *
     * @param transactionID id of the transaction to poll for
     * @param username      username, required for finalization
     * @param callback      callback to invoke with finalization result
     */
    public void asyncPollTransaction(String transactionID, String username, PIPollTransactionCallback callback) {
        Objects.requireNonNull(transactionID, "TransactionID is required!");
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
                    logError(e);
                }
                if (pollTransaction(transactionID)) {
                    runPoll.set(false);
                    PIResponse response = validateCheck(username, "", transactionID);
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
            logError("Cannot retrieve auth token without service account!");
            return null;
        }
        return endpoint.getAuthTokenFromServer();
    }

    /*
     * Stop the poll loop.
     */
    public void stopPolling() {
        runPoll.set(false);
    }

    /**
     * Retrieve information about the users tokens using a service account
     *
     * @param username username to get info for
     * @return list of TokenInfo or null if failure
     */
    public List<TokenInfo> getTokenInfo(String username) {
        Objects.requireNonNull(username);
        if (!checkServiceAccountAvailable()) {
            logError("Cannot retrieve token info without service account!");
            return null;
        }

        List<TokenInfo> ret = null;

        String response = endpoint.sendRequest(Constants.ENDPOINT_TOKEN,
                Collections.singletonMap(Constants.PARAM_KEY_USER, username),
                true,
                "GET");

        if (response != null && !response.isEmpty()) {
            JsonObject object;
            try {
                object = JsonParser.parseString(response).getAsJsonObject();
            } catch (JsonSyntaxException e) {
                logError(e);
                return null;
            }

            JsonObject result = object.getAsJsonObject("result");
            if (result != null) {
                JsonObject value = result.getAsJsonObject("value");
                if (value != null) {
                    JsonArray tokens = value.getAsJsonArray("tokens");
                    if (tokens != null) {
                        List<TokenInfo> infos = new ArrayList<>();
                        tokens.forEach(jsonValue -> infos.add(new TokenInfo(jsonValue.toString())));
                        ret = infos;
                    }
                }
            }
        }
        return ret;
    }

    public RolloutInfo tokenRollout(String username, String typeToEnroll) {
        if (!checkServiceAccountAvailable()) {
            logError("Cannot do rollout without service account!");
            return null;
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(Constants.PARAM_KEY_USER, username);
        params.put(Constants.PARAM_KEY_TYPE, typeToEnroll);
        params.put(Constants.PARAM_KEY_GENKEY, "1"); // Let the server generate the secret

        String response = endpoint.sendRequest(Constants.ENDPOINT_TOKEN_INIT, params, true, "POST");
        return new RolloutInfo(response);
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

    boolean checkServiceAccountAvailable() {
        return configuration.serviceAccountName != null && !configuration.serviceAccountName.isEmpty()
                && configuration.serviceAccountPass != null && !configuration.serviceAccountPass.isEmpty();
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

    void log(Throwable throwable) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.log(throwable);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(throwable.getMessage());
            } else {
                System.out.println(throwable.getLocalizedMessage());
            }
        }
    }

    private void logError(Throwable e) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.error(e);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(e.getMessage());
            } else {
                System.out.println(e.getLocalizedMessage());
            }
        }
    }

    private void logError(String e) {
        if (!configuration.disableLog) {
            if (this.log != null) {
                this.log.error(e);
            } else if (this.simpleLog != null) {
                this.simpleLog.pilog(e);
            } else {
                System.out.println(e);
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
        private PILoggerBridge logger = null;
        private boolean disableLog = false;
        private PISimpleLogBridge simpleLogBridge = null;

        /**
         * @param serverURL the server URL is mandatory to communicate with privacyIDEA.
         * @param userAgent the user agent that should be used in the http requests. Should refer to the plugin, something like "privacyIDEA-Keycloak"
         */
        public Builder(String serverURL, String userAgent) {
            this.userAgent = userAgent;
            this.serverURL = serverURL;
        }

        public Builder setSimpleLog(PISimpleLogBridge simpleLog) {
            this.simpleLogBridge = simpleLog;
            return this;
        }

        /**
         * Set a logger, which will receive log and error messages.
         * This is optional, if not set there will be no debug output.
         *
         * @param logger ILoggerBridge implementation
         * @return Builder
         */
        public Builder setLogger(PILoggerBridge logger) {
            this.logger = logger;
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

        public Builder disableLog() {
            this.disableLog = true;
            return this;
        }

        public PrivacyIDEA build() {
            Configuration configuration = new Configuration(serverURL, userAgent);
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
