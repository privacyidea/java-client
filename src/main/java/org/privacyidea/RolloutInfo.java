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
 */
package org.privacyidea;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import static org.privacyidea.PIResponse.getString;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
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
