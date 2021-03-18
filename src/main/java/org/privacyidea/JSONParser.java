package org.privacyidea;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.privacyidea.PIConstants.ASSERTIONCLIENTEXTENSIONS;
import static org.privacyidea.PIConstants.ATTRIBUTES;
import static org.privacyidea.PIConstants.AUTHENTICATORDATA;
import static org.privacyidea.PIConstants.CLIENTDATA;
import static org.privacyidea.PIConstants.CODE;
import static org.privacyidea.PIConstants.CREDENTIALID;
import static org.privacyidea.PIConstants.DETAIL;
import static org.privacyidea.PIConstants.ERROR;
import static org.privacyidea.PIConstants.ID;
import static org.privacyidea.PIConstants.INFO;
import static org.privacyidea.PIConstants.JSONRPC;
import static org.privacyidea.PIConstants.MAXFAIL;
import static org.privacyidea.PIConstants.MESSAGE;
import static org.privacyidea.PIConstants.MESSAGES;
import static org.privacyidea.PIConstants.MULTI_CHALLENGE;
import static org.privacyidea.PIConstants.OTPLEN;
import static org.privacyidea.PIConstants.REALMS;
import static org.privacyidea.PIConstants.RESULT;
import static org.privacyidea.PIConstants.SERIAL;
import static org.privacyidea.PIConstants.SIGNATURE;
import static org.privacyidea.PIConstants.SIGNATUREDATA;
import static org.privacyidea.PIConstants.STATUS;
import static org.privacyidea.PIConstants.TOKEN;
import static org.privacyidea.PIConstants.TOKENS;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.PIConstants.TRANSACTION_ID;
import static org.privacyidea.PIConstants.TYPE;
import static org.privacyidea.PIConstants.USERHANDLE;
import static org.privacyidea.PIConstants.USERNAME;
import static org.privacyidea.PIConstants.VALUE;
import static org.privacyidea.PIConstants.VERSION_NUMBER;
import static org.privacyidea.PIConstants.WEBAUTHN_SIGN_REQUEST;

public class JSONParser {

    private final PrivacyIDEA privacyIDEA;

    public JSONParser(PrivacyIDEA privacyIDEA) {
        this.privacyIDEA = privacyIDEA;
    }

    public String formatJson(String json) {
        if (json == null || json.isEmpty()) return "";

        JsonObject obj;
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error(e);
            return json;
        }

        return gson.toJson(obj);
    }

    String parseAuthToken(String serverResponse) {
        if (serverResponse != null && !serverResponse.isEmpty()) {
            JsonElement root = JsonParser.parseString(serverResponse);
            if (root != null) {
                try {
                    JsonObject obj = root.getAsJsonObject();
                    return obj.getAsJsonObject(RESULT).getAsJsonObject(VALUE).getAsJsonPrimitive(TOKEN).getAsString();
                } catch (Exception e) {
                    privacyIDEA.error("Response did not contain an authorization token: " + formatJson(serverResponse));
                }
            }
        } else {
            privacyIDEA.error("/auth response was empty or null!");
        }
        return "";
    }

    PIResponse parsePIResponse(String serverResponse) {
        PIResponse response = new PIResponse();
        if (serverResponse == null) return response;
        response.rawMessage = serverResponse;

        if (serverResponse.isEmpty()) return response;

        JsonObject obj;
        try {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error(e);
            return response;
        }

        response.id = getString(obj, ID);
        response.piVersion = getString(obj, VERSION_NUMBER);
        response.signature = getString(obj, SIGNATURE);
        response.jsonRPCVersion = getString(obj, JSONRPC);

        JsonObject result = obj.getAsJsonObject(RESULT);
        if (result != null) {
            response.status = getBoolean(result, STATUS);
            response.value = getBoolean(result, VALUE);

            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull()) {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                response.error = new PIResponse.Error();
                response.error.code = getInt(errObj, CODE);
                response.error.message = getString(errObj, MESSAGE);
            }
        }

        JsonElement detailElem = obj.get(DETAIL);
        if (detailElem != null && !detailElem.isJsonNull()) {
            JsonObject detail = obj.getAsJsonObject(DETAIL);
            response.message = getString(detail, MESSAGE);
            response.serial = getString(detail, SERIAL);
            response.transactionID = getString(detail, TRANSACTION_ID);
            response.type = getString(detail, TYPE);
            response.otpLength = getInt(detail, OTPLEN);

            JsonArray arrMessages = detail.getAsJsonArray(MESSAGES);
            if (arrMessages != null) {
                arrMessages.forEach(val -> {
                    if (val != null) {
                        response.messages.add(val.getAsString());
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
                        response.multichallenge.add(new WebAuthn(
                                getString(challenge, SERIAL),
                                getString(challenge, MESSAGE),
                                getString(challenge, TRANSACTION_ID),
                                webAuthnSignRequest
                        ));
                    } else {
                        response.multichallenge.add(new Challenge(
                                getString(challenge, SERIAL),
                                getString(challenge, MESSAGE),
                                getString(challenge, TRANSACTION_ID),
                                getString(challenge, TYPE)
                        ));
                    }
                }
            }
        }
        return response;
    }

    List<TokenInfo> parseTokenInfo(String serverResponse) {
        List<TokenInfo> ret = new ArrayList<>();
        JsonObject object;
        try {
            object = JsonParser.parseString(serverResponse).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error(e);
            return ret;
        }

        JsonObject result = object.getAsJsonObject(RESULT);
        if (result != null) {
            JsonObject value = result.getAsJsonObject(VALUE);
            if (value != null) {
                JsonArray tokens = value.getAsJsonArray(TOKENS);
                if (tokens != null) {
                    List<TokenInfo> infos = new ArrayList<>();
                    tokens.forEach(jsonValue -> infos.add(parseSingleTokenInfo(jsonValue.toString())));
                    ret = infos;
                }
            }
        }
        return ret;
    }

    private TokenInfo parseSingleTokenInfo(String json) {
        TokenInfo info = new TokenInfo();
        if (json == null || json.isEmpty()) {
            return info;
        }

        info.rawJson = json;

        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error(e);
            return info;
        }

        info.active = getBoolean(obj, "active");
        info.count = getInt(obj, "count");
        info.countWindow = getInt(obj, "count_window");
        info.description = getString(obj, "description");
        info.failCount = getInt(obj, "failcount");
        info.id = getInt(obj, ID);
        info.locked = getBoolean(obj, "locked");
        info.maxFail = getInt(obj, MAXFAIL);
        info.otpLen = getInt(obj, OTPLEN);
        info.resolver = getString(obj, "resolver");
        info.revoked = getBoolean(obj, "revoked");
        info.rolloutState = getString(obj, "rollout_state");
        info.serial = getString(obj, SERIAL);
        info.syncWindow = getInt(obj, "sync_window");
        info.tokenType = getString(obj, "tokentype");
        info.userEditable = getBoolean(obj, "user_editable");
        info.userID = getString(obj, "user_id");
        info.userRealm = getString(obj, "user_realm");
        info.username = getString(obj, USERNAME);

        JsonObject joInfo = obj.getAsJsonObject(INFO);
        if (joInfo != null) {
            joInfo.entrySet().forEach(entry -> {
                if (entry.getKey() != null && entry.getValue() != null) {
                    info.info.put(entry.getKey(), entry.getValue().getAsString());
                }
            });
        }

        JsonArray arrRealms = obj.getAsJsonArray(REALMS);
        if (arrRealms != null) {
            arrRealms.forEach(val -> {
                if (val != null) {
                    info.realms.add(val.getAsString());
                }
            });
        }
        return info;
    }

    RolloutInfo parseRolloutInfo(String serverResponse) {
        RolloutInfo rinfo = new RolloutInfo();
        rinfo.raw = serverResponse;
        rinfo.googleurl = new RolloutInfo.GoogleURL();
        rinfo.oathurl = new RolloutInfo.OATHURL();
        rinfo.otpkey = new RolloutInfo.OTPKey();

        if (serverResponse == null || serverResponse.isEmpty()) {
            return rinfo;
        }

        JsonObject obj;
        try {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error(e);
            return rinfo;
        }

        JsonObject detail = obj.getAsJsonObject("detail");
        if (detail != null) {
            JsonObject google = detail.getAsJsonObject("googleurl");
            if (google != null) {
                rinfo.googleurl.description = getString(google, "description");
                rinfo.googleurl.img = getString(google, "img");
                rinfo.googleurl.value = getString(google, "value");
            }

            JsonObject oath = detail.getAsJsonObject("oath");
            if (oath != null) {
                rinfo.oathurl.description = getString(oath, "description");
                rinfo.oathurl.img = getString(oath, "img");
                rinfo.oathurl.value = getString(oath, "value");
            }

            JsonObject otp = detail.getAsJsonObject("otpkey");
            if (otp != null) {
                rinfo.otpkey.description = getString(otp, "description");
                rinfo.otpkey.img = getString(otp, "img");
                rinfo.otpkey.value = getString(otp, "value");
                rinfo.otpkey.value_b32 = getString(otp, "value_b32");
            }

            rinfo.serial = getString(detail, "serial");
            rinfo.rolloutState = getString(detail, "rollout_state");
        }
        return rinfo;
    }
    
    Map<String, String> parseWebAuthnSignResponse(String json) {
        Map<String, String> params = new LinkedHashMap<>();
        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            privacyIDEA.error("WebAuthn sign response has the wrong format: " + e.getLocalizedMessage());
            return null;
        }

        params.put(CREDENTIALID, getString(obj, CREDENTIALID));
        params.put(CLIENTDATA, getString(obj, CLIENTDATA));
        params.put(SIGNATUREDATA, getString(obj, SIGNATUREDATA));
        params.put(AUTHENTICATORDATA, getString(obj, AUTHENTICATORDATA));

        // The userhandle and assertionclientextension fields are optional
        String userhandle = getString(obj, USERHANDLE);
        if (!userhandle.isEmpty()) {
            params.put(USERHANDLE, userhandle);
        }
        String extensions = getString(obj, ASSERTIONCLIENTEXTENSIONS);
        if (!extensions.isEmpty()) {
            params.put(ASSERTIONCLIENTEXTENSIONS, extensions);
        }
        return params;
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
}
