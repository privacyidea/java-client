import java.io.StringReader;
import java.security.SignedObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import netscape.javascript.JSObject;

public class TokenInfo {
    private boolean active = false;
    private int count = 0;
    private int countWindow = 0;
    private String description = "";
    private int failCount = 0;
    private int id = 0;
    private final Map<String, String> info = new HashMap<>();
    private boolean locked = false;
    private int maxFail = 0;
    private int otpLen = 0;
    private final List<String> realms = new ArrayList<>();
    private String resolver = "";
    private boolean revoked = false;
    private String rolloutState = "";
    private String serial = "";
    private int syncWindow = 0;
    private String tokenType = "";
    private boolean userEditable = false;
    private String userID = "";
    private String userRealm = "";
    private String username = "";
    private String rawJson = "";

    public TokenInfo(String rawJson) {
        if (rawJson == null || rawJson.isEmpty()) {
            return;
        }
        this.rawJson = rawJson;
        JsonObject object;
        try {
            object = Json.createReader(new StringReader(rawJson)).readObject();
        } catch (JsonException | IllegalStateException e) {
            e.printStackTrace();
            return;
        }

        this.active = object.getBoolean("active", false);
        this.count = object.getInt("count", 0);
        this.countWindow = object.getInt("count_window", 0);
        this.description = object.getString("description", "");
        this.failCount = object.getInt("failcount", 0);
        this.id = object.getInt("id", 0);
        this.locked = object.getBoolean("locked", false);
        this.maxFail = object.getInt("maxfail", 0);
        this.otpLen = object.getInt("otplen", 0);
        this.resolver = object.getString("resolver", "");
        this.revoked = object.getBoolean("revoked", false);
        this.rolloutState = object.getString("rollout_state", "");
        this.serial = object.getString("serial", "");
        this.syncWindow = object.getInt("sync_window", 0);
        this.tokenType = object.getString("tokentype", "");
        this.userEditable = object.getBoolean("user_editable", false);
        this.userID = object.getString("user_id", "");
        this.userRealm = object.getString("user_realm", "");
        this.username = object.getString("username", "");

        JsonObject infoObj = object.getJsonObject("info");
        if (infoObj != null) {
            infoObj.forEach((s, jsonValue) -> this.info.put(s, jsonValue.toString()));
        }

        JsonArray realmsArr = object.getJsonArray("realms");
        if (realmsArr != null) {
            realmsArr.forEach(jsonValue -> this.realms.add(jsonValue.toString()));
        }
    }

    public boolean isActive() {
        return active;
    }

    public int getCount() {
        return count;
    }

    public int getCountWindow() {
        return countWindow;
    }

    public String getDescription() {
        return description;
    }

    public int getFailCount() {
        return failCount;
    }

    public int getId() {
        return id;
    }

    public Map<String, String> getInfo() {
        return info;
    }

    public boolean isLocked() {
        return locked;
    }

    public int getMaxFail() {
        return maxFail;
    }

    public int getOtpLen() {
        return otpLen;
    }

    public List<String> getRealms() {
        return realms;
    }

    public String getResolver() {
        return resolver;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public String getRolloutState() {
        return rolloutState;
    }

    public String getSerial() {
        return serial;
    }

    public int getSyncWindow() {
        return syncWindow;
    }

    public String getTokenType() {
        return tokenType;
    }

    public boolean isUserEditable() {
        return userEditable;
    }

    public String getUserID() {
        return userID;
    }

    public String getUserRealm() {
        return userRealm;
    }

    public String getUsername() {
        return username;
    }
}
