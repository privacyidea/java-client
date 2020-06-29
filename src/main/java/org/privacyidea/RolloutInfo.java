package org.privacyidea;

import java.io.StringReader;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;

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

        JsonObject jsonObject;
        try {
            jsonObject = Json.createReader(new StringReader(json)).readObject();
        } catch (JsonException | IllegalStateException e) {
            e.printStackTrace();
            return;
        }

        JsonObject detail = jsonObject.getJsonObject("detail");
        if (detail != null) {
            JsonObject google = detail.getJsonObject("googleurl");
            if (google != null) {
                this.googleurl.description = google.getString("description", "");
                this.googleurl.img = google.getString("img", "");
                this.googleurl.value = google.getString("value", "");
            }

            JsonObject oath = detail.getJsonObject("oathurl");
            if (oath != null) {
                this.oathurl.description = oath.getString("description", "");
                this.oathurl.img = oath.getString("img", "");
                this.oathurl.value = oath.getString("value", "");
            }

            JsonObject otp = detail.getJsonObject("otpkey");
            if (otp != null) {
                this.otpkey.description = otp.getString("description", "");
                this.otpkey.img = otp.getString("img", "");
                this.otpkey.value = otp.getString("value", "");
                this.otpkey.value_b32 = otp.getString("value_b32", "");
            }

            this.serial = detail.getString("serial", "");
            this.rolloutState = detail.getString("rollout_state", "");
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
