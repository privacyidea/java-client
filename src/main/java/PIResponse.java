
import javax.json.*;
import javax.json.stream.JsonParsingException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PIResponse {

    private String message;
    private List<String> messages = new ArrayList<>();
    private List<Challenge> mutlichallenge = new ArrayList<>();
    private String transaction_id;
    private List<String> transaction_ids = new ArrayList<>();
    private String serial;
    private String threadID;
    private String id;
    private String jsonRPCVersion;
    private boolean status;
    private boolean value;
    private String version; // e.g. privacyIDEA 3.2.1.
    private String versionNumber; // e.g. 3.2.1
    private String rawMessage;
    private String time;
    private String signature;

    public PIResponse(String json) {
        if (json == null) return;
        this.rawMessage = json;
        JsonObject o;
        try {
            o = Json.createReader(new StringReader(json)).readObject();
        } catch (JsonException | IllegalStateException e) {
            e.printStackTrace();
            return;
        }

        this.id = String.valueOf(o.getInt("id", 0));
        this.version = o.getString("version", "");
        this.versionNumber = o.getString("versionnumber", "");

        JsonNumber jNum = o.getJsonNumber("time");//.doubleValue();
        if (jNum != null) {
            this.time = String.valueOf(jNum.doubleValue());
        }
        this.signature = o.getString("signature", "");
        this.jsonRPCVersion = o.getString("jsonrpc", "");

        JsonObject result = o.getJsonObject("result");
        if (result != null) {
            this.status = result.getBoolean("status", false);
            this.value = result.getBoolean("value", false);
        }

        JsonObject detail = o.getJsonObject("detail");
        if (detail != null) {
            this.message = detail.getString("message", "");
            this.serial = detail.getString("serial", "");
            this.threadID = String.valueOf(detail.getInt("threadid", 0));
            this.transaction_id = detail.getString("transaction_id", "");

            // The following is included if challenges were triggered
            JsonArray arrMessages = detail.getJsonArray("messages");
            if (arrMessages != null) {
                for (JsonValue value : arrMessages) {
                    if (value.getValueType() == JsonValue.ValueType.STRING) {
                        messages.add(((JsonString) value).toString());
                    }
                }
            }

            JsonArray arrChallenges = detail.getJsonArray("multi_challenge");
            if (arrChallenges != null) {
                for (int i = 0; i < arrChallenges.size(); i++) {
                    JsonObject obj = arrChallenges.getJsonObject(i);
                    String type = obj.getString("type");

                    TokenType ttype;
                    switch (type) {
                        case "hotp":
                            ttype = TokenType.HOTP;
                            break;
                        case "totp":
                            ttype = TokenType.TOTP;
                            break;
                        case "push":
                            ttype = TokenType.PUSH;
                            break;
                        default:
                            ttype = TokenType.HOTP;
                            break;
                    }

                    mutlichallenge.add(new Challenge(
                            obj.getString("serial"),
                            obj.getString("message"),
                            obj.getString("transaction_id"),
                            ttype
                    ));
                }
            }

        }
    }

    public String getMessage() {
        return message;
    }

    public List<TokenType> getTriggeredTokenTypes() {
        return mutlichallenge.stream().map(c -> {
            return c.type;
        }).distinct().collect(Collectors.toList());
    }

    public List<String> getMessages() {
        return messages;
    }

    public List<Challenge> getMultiChallenge() {
        return mutlichallenge;
    }

    public String getTransactionID() {
        return transaction_id;
    }

    public List<String> getTransactionIDs() {
        return mutlichallenge.stream().map(c -> c.transaction_id).collect(Collectors.toList());
    }

    public String getSerial() {
        return serial;
    }

    public String getThreadID() {
        return threadID;
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

    public String getTime() {
        return time;
    }

    public String getVersion() {
        return version;
    }

    public String getVersionNumber() {
        return versionNumber;
    }

    public String getSignature() {
        return signature;
    }

    public String getRawMessage() {
        return rawMessage;
    }
}
