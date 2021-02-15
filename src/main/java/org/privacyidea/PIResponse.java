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
 *
 */
package org.privacyidea;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.privacyidea.PIConstants.ATTRIBUTES;
import static org.privacyidea.PIConstants.CODE;
import static org.privacyidea.PIConstants.DETAIL;
import static org.privacyidea.PIConstants.ERROR;
import static org.privacyidea.PIConstants.ID;
import static org.privacyidea.PIConstants.JSONRPC;
import static org.privacyidea.PIConstants.MESSAGE;
import static org.privacyidea.PIConstants.MESSAGES;
import static org.privacyidea.PIConstants.MULTI_CHALLENGE;
import static org.privacyidea.PIConstants.OTPLEN;
import static org.privacyidea.PIConstants.RESULT;
import static org.privacyidea.PIConstants.SERIAL;
import static org.privacyidea.PIConstants.SIGNATURE;
import static org.privacyidea.PIConstants.STATUS;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.PIConstants.TRANSACTION_ID;
import static org.privacyidea.PIConstants.TYPE;
import static org.privacyidea.PIConstants.VALUE;
import static org.privacyidea.PIConstants.VERSION;
import static org.privacyidea.PIConstants.VERSION_NUMBER;
import static org.privacyidea.PIConstants.WEBAUTHN_SIGN_REQUEST;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class PIResponse {

    private String message;
    private final List<String> messages = new ArrayList<>();
    private final List<Challenge> multichallenge = new ArrayList<>();
    private String transaction_id;
    private final List<String> transaction_ids = new ArrayList<>();
    private String serial;
    private String id;
    private String jsonRPCVersion;
    private boolean status = false;
    private boolean value = false;
    private String version; // e.g. privacyIDEA 3.2.1.
    private String versionNumber; // e.g. 3.2.1
    private String rawMessage;
    private String time;
    private String signature;
    private String type; // Type of token that was matching the request
    private int otplen = 0;
    private String threadID;
    private Error error = null;

    public PIResponse(String json) {
        if (json == null) return;
        this.rawMessage = json;

        if (json.isEmpty()) return;

        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return;
        }

        this.id = getString(obj, ID);
        this.version = getString(obj, VERSION);
        this.versionNumber = getString(obj, VERSION_NUMBER);
        this.signature = getString(obj, SIGNATURE);
        this.jsonRPCVersion = getString(obj, JSONRPC);

        JsonObject result = obj.getAsJsonObject(RESULT);
        if (result != null) {
            this.status = getBoolean(result, STATUS);
            this.value = getBoolean(result, VALUE);

            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull()) {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                this.error = new Error();
                this.error.code = getInt(errObj, CODE);
                this.error.message = getString(errObj, MESSAGE);
            }
        }

        JsonElement detailElem = obj.get(DETAIL);
        if (detailElem != null && !detailElem.isJsonNull()) {
            JsonObject detail = obj.getAsJsonObject(DETAIL);
            this.message = getString(detail, MESSAGE);
            this.serial = getString(detail, SERIAL);
            this.transaction_id = getString(detail, TRANSACTION_ID);
            this.type = getString(detail, TYPE);
            this.otplen = getInt(detail, OTPLEN);

            JsonArray arrMessages = detail.getAsJsonArray(MESSAGES);
            if (arrMessages != null) {
                arrMessages.forEach(val -> {
                    if (val != null) {
                        this.messages.add(val.getAsString());
                    }
                });
            }

            JsonArray arrChallenges = detail.getAsJsonArray(MULTI_CHALLENGE);
            if (arrChallenges != null) {
                for (int i = 0; i < arrChallenges.size(); i++) {
                    JsonObject challenge = arrChallenges.get(i).getAsJsonObject();
                    if (TOKEN_TYPE_WEBAUTHN.equals(getString(challenge, TYPE))) {
                        String webAuthnSignRequest = "";
                        JsonElement attrElem = challenge.get(ATTRIBUTES);
                        if (attrElem != null && !attrElem.isJsonNull()) {
                            JsonElement webauthnElem = attrElem.getAsJsonObject().get(WEBAUTHN_SIGN_REQUEST);
                            if (webauthnElem != null && !webauthnElem.isJsonNull()) {
                                webAuthnSignRequest = webauthnElem.toString();
                            }
                        }
                        multichallenge.add(new WebAuthn(
                                getString(challenge, SERIAL),
                                getString(challenge, MESSAGE),
                                getString(challenge, TRANSACTION_ID),
                                webAuthnSignRequest
                        ));
                    } else {
                        multichallenge.add(new Challenge(
                                getString(challenge, SERIAL),
                                getString(challenge, MESSAGE),
                                getString(challenge, TRANSACTION_ID),
                                getString(challenge, TYPE)
                        ));
                    }
                }
            }
        }
    }

    public static class Error {
        private int code = 0;
        private String message = "";

        public int getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }
    }

    static boolean getBoolean(JsonObject obj, String name) {
        JsonPrimitive prim = obj.getAsJsonPrimitive(name);
        return prim != null && prim.getAsBoolean();
    }

    static int getInt(JsonObject obj, String name) {
        JsonPrimitive prim = obj.getAsJsonPrimitive(name);
        return prim == null ? 0 : prim.getAsInt();
    }

    static String getString(JsonObject obj, String name) {
        JsonPrimitive prim = obj.getAsJsonPrimitive(name);
        return prim == null ? "" : prim.getAsString();
    }

    public Error getError() {
        return error;
    }

    public String getMessage() {
        return message;
    }

    /**
     * @return list of token types that were triggered or an empty list
     */
    public List<String> getTriggeredTokenTypes() {
        return multichallenge.stream().map(Challenge::getType).distinct().collect(Collectors.toList());
    }

    /**
     * @return a list of messages for the challenges that were triggered or an empty list
     */
    public List<String> getMessages() {
        return messages;
    }

    /**
     * @return a list of challenges that were triggered or an empty list if none were triggered
     */
    public List<Challenge> getMultiChallenge() {
        return multichallenge;
    }

    /**
     * @return the transaction id that was triggered or an empty string if nothing was triggered
     */
    public String getTransactionID() {
        return transaction_id;
    }

    /**
     * @return list which might be empty if no transactions were triggered
     */
    public List<String> getTransactionIDs() {
        return multichallenge.stream().map(Challenge::getTransactionID).distinct().collect(Collectors.toList());
    }

    public String getSerial() {
        return serial;
    }

    public String getID() {
        return id;
    }

    public String getJSONRPCVersion() {
        return jsonRPCVersion;
    }

    public boolean getStatus() {
        return status;
    }

    public boolean getValue() {
        return value;
    }

    public String getPrivacyIDEAVersion() {
        return version;
    }

    public String getPrivacyIDEAVersionNumber() {
        return versionNumber;
    }

    public String getSignature() {
        return signature;
    }

    public String getRawMessage() {
        return rawMessage;
    }

    public String getType() {
        return type;
    }

    public int getOTPlength() {
        return otplen;
    }

    @Override
    public String toString() {
        return rawMessage;
    }
}
