package org.privacyidea;

import com.google.gson.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

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

        this.id = getString(obj, "id");
        this.version = getString(obj, "version");
        this.versionNumber = getString(obj, "versionnumber");
        this.signature = getString(obj, "signature");
        this.jsonRPCVersion = getString(obj, "jsonrpc");

        JsonObject result = obj.getAsJsonObject("result");
        if (result != null) {
            this.status = getBoolean(result, "status");
            this.value = getBoolean(result, "value");

            JsonElement errElem = result.get("error");
            if (errElem != null && !errElem.isJsonNull()) {
                JsonObject errObj = result.getAsJsonObject("error");
                this.error = new Error();
                this.error.code = getInt(errObj, "code");
                this.error.message = getString(errObj, "message");
            }
        }
        JsonElement detailElem = obj.get("detail");
        if (detailElem != null && !detailElem.isJsonNull()) {
            JsonObject detail = obj.getAsJsonObject("detail");
            this.message = getString(detail, "message");
            this.serial = getString(detail, "serial");
            this.transaction_id = getString(detail, "transaction_id");
            this.type = getString(detail, "type");
            this.otplen = getInt(detail, "otplen");


            JsonArray arrMessages = detail.getAsJsonArray("messages");
            if (arrMessages != null) {
                arrMessages.forEach(val -> {
                    if (val != null) {
                        this.messages.add(val.getAsString());
                    }
                });
            }

            JsonArray arrChallenges = detail.getAsJsonArray("multi_challenge");
            if (arrChallenges != null) {
                for (int i = 0; i < arrChallenges.size(); i++) {
                    JsonObject challenge = arrChallenges.get(i).getAsJsonObject();
                    if (getString(challenge,"type") == "WebAuthn") {
                        multichallenge.add(new WebAuthn(
                                getString(challenge, "serial"),
                                getString(challenge, "message"),
                                getString(challenge, "transaction_id"),
                                getString(challenge, "type"),
                                getString(obj.getAsJsonObject("challenge.detail.attributes"), "WebAuthnSignRequest")
                        ));
                    }else {
                        multichallenge.add(new Challenge(
                                getString(challenge, "serial"),
                                getString(challenge, "message"),
                                getString(challenge, "transaction_id"),
                                getString(challenge, "type")
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
