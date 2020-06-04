import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonValue;

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

    public PIResponse(String json) {
        if (json == null) return;
        this.rawMessage = json;

        if (json.isEmpty()) return;

        JsonObject jsonObject;
        try {
            jsonObject = Json.createReader(new StringReader(json)).readObject();
        } catch (JsonException | IllegalStateException e) {
            e.printStackTrace();
            return;
        }

        this.id = String.valueOf(jsonObject.getInt("id", 0));
        this.version = jsonObject.getString("version", "");
        this.versionNumber = jsonObject.getString("versionnumber", "");
        /*
        JsonNumber jNumTime = jsonObject.getJsonNumber("time");
        if (jNumTime != null) {
            this.time = String.valueOf(jNumTime.doubleValue());
        }
        */
        this.signature = jsonObject.getString("signature", "");
        this.jsonRPCVersion = jsonObject.getString("jsonrpc", "");

        JsonObject result = jsonObject.getJsonObject("result");
        if (result != null) {
            this.status = result.getBoolean("status", false);
            this.value = result.getBoolean("value", false);
        }

        JsonObject detail = jsonObject.getJsonObject("detail");
        if (detail != null) {
            this.message = detail.getString("message", "");
            this.serial = detail.getString("serial", "");
            this.transaction_id = detail.getString("transaction_id", "");
            this.type = detail.getString("type", null);
            this.otplen = detail.getInt("otplen", 0);
            /*
            JsonNumber jNumThreadID = detail.getJsonNumber("threadid");
            if (jNumThreadID != null) {
                this.threadID = String.valueOf(jNumThreadID.bigIntegerValue());
            }
            */
            // The following is included if challenges were triggered
            JsonArray arrMessages = detail.getJsonArray("messages");
            if (arrMessages != null) {
                arrMessages.forEach(jsonValue -> this.messages.add(jsonValue.toString()));
            }

            JsonArray arrChallenges = detail.getJsonArray("multi_challenge");
            if (arrChallenges != null) {
                for (int i = 0; i < arrChallenges.size(); i++) {
                    JsonObject obj = arrChallenges.getJsonObject(i);
                    multichallenge.add(new Challenge(
                            obj.getString("serial"),
                            obj.getString("message"),
                            obj.getString("transaction_id"),
                            obj.getString("type")
                    ));
                }
            }
        }
    }

    public String getMessage() {
        return message;
    }

    public List<String> getTriggeredTokenTypes() {
        return multichallenge.stream().map(Challenge::getType).distinct().collect(Collectors.toList());
    }

    public List<String> getMessages() {
        return messages;
    }

    public List<Challenge> getMultiChallenge() {
        return multichallenge;
    }

    public String getTransactionID() {
        return transaction_id;
    }

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
