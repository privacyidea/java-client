import java.util.Arrays;
import java.util.List;

public class Constants {

    private Constants() {
    }

    static final String PROVIDER_ID = "privacyidea-authenticator";

    static final String GET = "GET";
    static final String POST = "POST";

    static final String ENDPOINT_AUTH = "/auth";
    static final String ENDPOINT_TOKEN_INIT = "/token/init";
    static final String ENDPOINT_TRIGGERCHALLENGE = "/validate/triggerchallenge";
    static final String ENDPOINT_POLL_TRANSACTION = "/validate/polltransaction";
    static final String ENDPOINT_VALIDATE_CHECK = "/validate/check";
    static final String ENDPOINT_TOKEN = "/token/";

    static final int DEFAULT_POLLING_INTERVAL = 1; // Will be used if single value from config cannot be parsed
    static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(4, 2, 1, 1, 2); // Will be used if no intervals are specified

    static final String PARAM_KEY_USERNAME = "username";
    static final String PARAM_KEY_USER = "user";
    static final String PARAM_KEY_PASSWORD = "password";
    static final String PARAM_KEY_PASS = "pass";
    static final String PARAM_KEY_TYPE = "type";
    static final String PARAM_KEY_TRANSACTION_ID = "transaction_id";
    static final String PARAM_KEY_REALM = "realm";
}
