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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.privacyidea.PIConstants.ID;
import static org.privacyidea.PIConstants.INFO;
import static org.privacyidea.PIConstants.MAXFAIL;
import static org.privacyidea.PIConstants.OTPLEN;
import static org.privacyidea.PIConstants.REALMS;
import static org.privacyidea.PIConstants.SERIAL;
import static org.privacyidea.PIConstants.USERNAME;
import static org.privacyidea.PIResponse.getBoolean;
import static org.privacyidea.PIResponse.getInt;
import static org.privacyidea.PIResponse.getString;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
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

        JsonObject obj;
        try {
            obj = JsonParser.parseString(rawJson).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return;
        }

        this.active = getBoolean(obj, "active");
        this.count = getInt(obj, "count");
        this.countWindow = getInt(obj, "count_window");
        this.description = getString(obj, "description");
        this.failCount = getInt(obj, "failcount");
        this.id = getInt(obj, ID);
        this.locked = getBoolean(obj, "locked");
        this.maxFail = getInt(obj, MAXFAIL);
        this.otpLen = getInt(obj, OTPLEN);
        this.resolver = getString(obj, "resolver");
        this.revoked = getBoolean(obj, "revoked");
        this.rolloutState = getString(obj, "rollout_state");
        this.serial = getString(obj, SERIAL);
        this.syncWindow = getInt(obj, "sync_window");
        this.tokenType = getString(obj, "tokentype");
        this.userEditable = getBoolean(obj, "user_editable");
        this.userID = getString(obj, "user_id");
        this.userRealm = getString(obj, "user_realm");
        this.username = getString(obj, USERNAME);

        JsonObject info = obj.getAsJsonObject(INFO);
        if (info != null) {
            info.entrySet().forEach(entry -> {
                if (entry.getKey() != null && entry.getValue() != null) {
                    this.info.put(entry.getKey(), entry.getValue().getAsString());
                }
            });
        }

        JsonArray arrRealms = obj.getAsJsonArray(REALMS);
        if (arrRealms != null) {
            arrRealms.forEach(val -> {
                if (val != null) {
                    this.realms.add(val.getAsString());
                }
            });
        }
    }

    public String getRawJson() {
        return rawJson;
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
