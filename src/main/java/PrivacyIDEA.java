import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

public class PrivacyIDEA {

    private final Configuration configuration;
    private final ILoggerBridge log;
    private final AtomicBoolean runPoll = new AtomicBoolean(true);
    private final Endpoint endpoint;

    private PrivacyIDEA(Configuration configuration, ILoggerBridge logger) {
        this.log = logger;
        this.configuration = configuration;
        this.endpoint = new Endpoint(this, configuration.serverURL, configuration.doSSLVerify,
                configuration.serviceAccountName, configuration.serviceAccountPass);
    }

    public PIResponse validateCheck(String username, String otp) {
        return validateCheck(username, otp, null);
    }

    public PIResponse validateCheck(String username, String otp, String transaction_id) {
        Map<String, String> params = new LinkedHashMap<>();

        if (otp == null)
            otp = "";

        params.put(Constants.PARAM_KEY_USER, username);
        params.put(Constants.PARAM_KEY_PASS, otp);

        if (transaction_id != null && !transaction_id.isEmpty())
            params.put(Constants.PARAM_KEY_TRANSACTION_ID, transaction_id);

        String response = endpoint.sendRequest(Constants.ENDPOINT_VALIDATE_CHECK, params, false, "POST");

        // TODO return null object or null upon error or empty response
        if (response == null || response.isEmpty())
            return null;

        return new PIResponse(response);
    }

    /**
     * Trigger all possible challenges for the given username using a service account
     *
     * @param username username to trigger challenges for
     * @return the server response or null if error
     */
    public PIResponse triggerChallenges(String username) {
        Objects.requireNonNull(username, "Username is required!");
        if (configuration.serviceAccountName == null || configuration.serviceAccountName.isEmpty()
                || configuration.serviceAccountPass == null || configuration.serviceAccountPass.isEmpty()) {
            log.error("No service account configured. Cannot trigger challenges");
            return null;
        }

        return new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_TRIGGERCHALLENGE,
                Collections.singletonMap(Constants.PARAM_KEY_USER, username), true, "POST"));
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

    public void asyncPollTransaction(String transactionID, String username, IPollTransactionCallback callback) {
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
                    e.printStackTrace();
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

    public String getAuthToken() {
        if (!checkServiceAccountAvailable()) return null;
        return endpoint.getAuthToken();
    }

    private boolean checkServiceAccountAvailable() {
        return configuration.serviceAccountName != null && !configuration.serviceAccountName.isEmpty()
                && configuration.serviceAccountPass != null && !configuration.serviceAccountPass.isEmpty();
    }

    public void stopPolling() {
        runPoll.set(false);
    }

    void log(String message) {
        if (this.log != null) {
            this.log.log(message);
        }
    }

    void log(Throwable throwable) {
        if (this.log != null) {
            this.log.log(throwable);
        }
    }

    public static class Builder {
        private String serverURL = "";
        private String realm = "";
        private boolean doSSLVerify = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private boolean doEnrollToken = false;
        private String enrollingTokenType = "hotp";
        private List<Integer> pollingIntervals = Collections.singletonList(1);
        private ILoggerBridge logger = null;

        public Builder(String serverURL) {
            this.serverURL = serverURL;
        }

        public Builder setLogger(ILoggerBridge logger) {
            this.logger = logger;
            return this;
        }

        public Builder setRealm(String realm) {
            this.realm = realm;
            return this;
        }

        public Builder setSSLVerify(boolean doSSLVerify) {
            this.doSSLVerify = doSSLVerify;
            return this;
        }

        public Builder setServiceAccount(String serviceAccountName, String serviceAccountPass) {
            this.serviceAccountName = serviceAccountName;
            this.serviceAccountPass = serviceAccountPass;
            return this;
        }

        public Builder setEnrollToken(boolean doEnrollToken) {
            this.doEnrollToken = doEnrollToken;
            return this;
        }

        // TODO which token types are supported here?
        public Builder setEnrollingTokenType(String tokenType) {
            this.enrollingTokenType = tokenType;
            return this;
        }

        public Builder setPollingIntervals(List<Integer> intervals) {
            this.pollingIntervals = intervals;
            return this;
        }

        public PrivacyIDEA build() {
            Configuration configuration = new Configuration(serverURL);
            configuration.realm = realm;
            configuration.doSSLVerify = doSSLVerify;
            configuration.serviceAccountName = serviceAccountName;
            configuration.serviceAccountPass = serviceAccountPass;
            configuration.doEnrollToken = doEnrollToken;
            configuration.enrollingTokenType = enrollingTokenType;
            configuration.pollingIntervals = pollingIntervals;

            return new PrivacyIDEA(configuration, logger);
        }
    }
}
