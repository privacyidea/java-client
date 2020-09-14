package org.privacyidea;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import static org.privacyidea.PIResponse.getString;

public class RolloutInfo {

    public final GoogleURL googleurl;
    public final OATHURL oathurl;
    public final OTPKey otpkey;
    public final String raw;
    public String serial;
    public String rolloutState;

    public RolloutInfo(String json) {
        this.raw = json;
        this.googleurl = new GoogleURL();
        this.oathurl = new OATHURL();
        this.otpkey = new OTPKey();

        if (json == null || json.isEmpty()) {
            return;
        }

        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return;
        }

        JsonObject detail = obj.getAsJsonObject("detail");
        if (detail != null) {
            JsonObject google = detail.getAsJsonObject("googleurl");
            if (google != null) {
                this.googleurl.description = getString(google, "description");
                this.googleurl.img = getString(google, "img");
                this.googleurl.value = getString(google, "value");
            }

            JsonObject oath = detail.getAsJsonObject("oath");
            if (oath != null) {
                this.oathurl.description = getString(oath, "description");
                this.oathurl.img = getString(oath, "img");
                this.oathurl.value = getString(oath, "value");
            }

            JsonObject otp = detail.getAsJsonObject("otpkey");
            if (otp != null) {
                this.otpkey.description = getString(otp, "description");
                this.otpkey.img = getString(otp, "img");
                this.otpkey.value = getString(otp, "value");
                this.otpkey.value_b32 = getString(otp, "value_b32");
            }

            this.serial = getString(detail, "serial");
            this.rolloutState = getString(detail, "rollout_state");
        }

    }

    public static class GoogleURL {
        public String description = "", img = "", value = "";
    }

    public static class OATHURL {
        public String description = "", img = "", value = "";
    }

    public static class OTPKey {
        public String description = "", img = "", value = "", value_b32 = "";
    }
}
