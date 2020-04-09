import jdk.internal.jline.internal.Nullable;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class PrivacyIDEA {

    private Configuration configuration;
    private ILoggerBridge log;
    private AtomicBoolean runPoll = new AtomicBoolean(true);
    private Endpoint endpoint;

    private PrivacyIDEA(Configuration configuration, ILoggerBridge logger) {
        this.log = logger;
        this.configuration = configuration;
        this.endpoint = new Endpoint(configuration.serverURL, configuration.doSSLVerify, logger,
                configuration.serviceAccountName, configuration.serviceAccountPass);
    }

    public PIResponse validateCheck(String username, String otp) {
        return validateCheck(username, otp, null);
    }

    public PIResponse validateCheck(String username, String otp, @Nullable String transaction_id) {
        // TODO check empty user/otp?

        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAM_KEY_USER, username);
        params.put(Constants.PARAM_KEY_PASS, otp);
        if (transaction_id != null && !transaction_id.isEmpty())
            params.put(Constants.PARAM_KEY_TRANSACTION_ID, transaction_id);

        return new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_VALIDATE_CHECK, params, false, "POST"));
    }

    public PIResponse triggerChallenges(String username) {
        if (configuration.serviceAccountName == null || configuration.serviceAccountName.isEmpty()
                || configuration.serviceAccountPass == null || configuration.serviceAccountPass.isEmpty()) {
            log.error("No service account configured. Cannot trigger challenges");
            return null;
        }

        return new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_TRIGGERCHALLENGE,
                Collections.singletonMap(Constants.PARAM_KEY_USER, username), true, "POST"));
    }

    boolean pollTransaction(String transaction_id) {
        PIResponse response = new PIResponse(endpoint.sendRequest(Constants.ENDPOINT_POLL_TRANSACTION,
                Collections.singletonMap(Constants.PARAM_KEY_TRANSACTION_ID, transaction_id),
                false, "GET"));

        return response.getValue();
    }

    void stopPolling() {
        runPoll.set(false);
    }

    void asyncPollTransaction(String transction_id, String username, IPollTransactionCallback callback) {
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
                if (pollTransaction(transction_id)) {
                    runPoll.set(false);
                    PIResponse response = validateCheck(username, "", transction_id);
                    callback.transactionFinalized(response.getValue());
                    break;
                }
            }
        });
        t.start();
    }

    public static class Builder {
        private String serverURL = "";
        private String realm = "";
        private boolean doSSLVerify = true;
        private boolean doTriggerChallenge = true;
        private String serviceAccountName = "";
        private String serviceAccountPass = "";
        private boolean doEnrollToken = false;
        private TokenType enrollingTokenType = TokenType.HOTP;
        private List<Integer> pollingIntervals = Collections.singletonList(1);
        private ILoggerBridge logger;

        public Builder(String serverURL, ILoggerBridge logger) {
            this.serverURL = serverURL;
            this.logger = logger;
        }

        public Builder setRealm(String realm) {
            this.realm = realm;
            return this;
        }

        public Builder setSSLVerify(boolean doSSLVerify) {
            this.doSSLVerify = doSSLVerify;
            return this;
        }

        public Builder setTriggerChallenge(boolean doTriggerChallenge) {
            this.doTriggerChallenge = doTriggerChallenge;
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

        public Builder setEnrollingTokenType(TokenType tokenType) {
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
            configuration.doTriggerChallenge = doTriggerChallenge;
            configuration.serviceAccountName = serviceAccountName;
            configuration.serviceAccountPass = serviceAccountPass;
            configuration.doEnrollToken = doEnrollToken;
            configuration.enrollingTokenType = enrollingTokenType;
            configuration.pollingIntervals = pollingIntervals;

            return new PrivacyIDEA(configuration, logger);
        }
    }

}
