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

import java.util.Arrays;
import java.util.List;

public class PIConstants
{
    private PIConstants()
    {
    }

    public static final String GET = "GET";
    public static final String POST = "POST";

    // ENDPOINTS
    public static final String ENDPOINT_AUTH = "/auth";
    public static final String ENDPOINT_TOKEN_INIT = "/token/init";
    public static final String ENDPOINT_TRIGGERCHALLENGE = "/validate/triggerchallenge";
    public static final String ENDPOINT_POLLTRANSACTION = "/validate/polltransaction";
    public static final String ENDPOINT_VALIDATE_CHECK = "/validate/check";
    public static final String ENDPOINT_TOKEN = "/token/";

    public static final String HEADER_ORIGIN = "Origin";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_USER_AGENT = "User-Agent";

    // TOKEN TYPES
    public static final String TOKEN_TYPE_PUSH = "push";
    public static final String TOKEN_TYPE_WEBAUTHN = "webauthn";
    public static final String TOKEN_TYPE_U2F = "u2f";

    // JSON KEYS
    public static final String USERNAME = "username";
    public static final String USER = "user";
    public static final String PASSWORD = "password";
    public static final String PASS = "pass";
    public static final String SERIAL = "serial";
    public static final String TYPE = "type";
    public static final String TRANSACTION_ID = "transaction_id";
    public static final String REALM = "realm";
    public static final String REALMS = "realms";
    public static final String GENKEY = "genkey";
    public static final String OTPKEY = "otpkey";
    public static final String RESULT = "result";
    public static final String VALUE = "value";
    public static final String TOKENS = "tokens";
    public static final String TOKEN = "token";
    public static final String PREFERRED_CLIENT_MODE = "preferred_client_mode";
    public static final String MESSAGE = "message";
    public static final String CLIENT_MODE = "client_mode";
    public static final String IMAGE = "image";
    public static final String MESSAGES = "messages";
    public static final String MULTI_CHALLENGE = "multi_challenge";
    public static final String ATTRIBUTES = "attributes";
    public static final String DETAIL = "detail";
    public static final String OTPLEN = "otplen";
    public static final String CODE = "code";
    public static final String ERROR = "error";
    public static final String STATUS = "status";
    public static final String JSONRPC = "jsonrpc";
    public static final String SIGNATURE = "signature";
    public static final String VERSION_NUMBER = "versionnumber";
    public static final String AUTHENTICATION = "authentication";
    public static final String ID = "id";
    public static final String MAXFAIL = "maxfail";
    public static final String INFO = "info";

    // WebAuthn params
    public static final String WEBAUTHN_SIGN_REQUEST = "webAuthnSignRequest";
    public static final String CREDENTIALID = "credentialid";
    public static final String CLIENTDATA = "clientdata";
    public static final String SIGNATUREDATA = "signaturedata";
    public static final String AUTHENTICATORDATA = "authenticatordata";
    public static final String USERHANDLE = "userhandle";
    public static final String ASSERTIONCLIENTEXTENSIONS = "assertionclientextensions";


    // These will be excluded from url encoding
    public static final List<String>
            WEBAUTHN_PARAMETERS =
            Arrays.asList(CREDENTIALID, CLIENTDATA, SIGNATUREDATA, AUTHENTICATORDATA, USERHANDLE,
                          ASSERTIONCLIENTEXTENSIONS);
}
