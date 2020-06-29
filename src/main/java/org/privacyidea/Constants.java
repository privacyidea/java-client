package org.privacyidea;

import java.util.Arrays;
import java.util.List;

public class Constants {

    private Constants() {
    }

    public static final String GET = "GET";
    public static final String POST = "POST";

    public static final String ENDPOINT_AUTH = "/auth";
    public static final String ENDPOINT_TOKEN_INIT = "/token/init";
    public static final String ENDPOINT_TRIGGERCHALLENGE = "/validate/triggerchallenge";
    public static final String ENDPOINT_POLL_TRANSACTION = "/validate/polltransaction";
    public static final String ENDPOINT_VALIDATE_CHECK = "/validate/check";
    public static final String ENDPOINT_TOKEN = "/token/";

    public static final int DEFAULT_POLLING_INTERVAL = 1; // Will be used if single value from config cannot be parsed
    public static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(4, 2, 1, 1, 2); // Will be used if no intervals are specified

    public static final String PARAM_KEY_USERNAME = "username";
    public static final String PARAM_KEY_USER = "user";
    public static final String PARAM_KEY_PASSWORD = "password";
    public static final String PARAM_KEY_PASS = "pass";
    public static final String PARAM_KEY_SERIAL = "serial";
    public static final String PARAM_KEY_TYPE = "type";
    public static final String PARAM_KEY_TRANSACTION_ID = "transaction_id";
    public static final String PARAM_KEY_REALM = "realm";
    public static final String PARAM_KEY_GENKEY = "genkey";
}
