/*
 * Copyright 2023 NetKnights GmbH - nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
 * - Modified
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License here:
 * <a href="http://www.apache.org/licenses/LICENSE-2.0">License</a>
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import com.google.gson.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.privacyidea.PIConstants.*;

public class JSONParser
{
    private final PrivacyIDEA privacyIDEA;

    public JSONParser(PrivacyIDEA privacyIDEA)
    {
        this.privacyIDEA = privacyIDEA;
    }

    /**
     * Format a json string with indentation.
     *
     * @param json json string
     * @return formatted json string
     */
    public String formatJson(String json)
    {
        if (json == null || json.isEmpty())
        {
            return "";
        }

        JsonObject obj;
        Gson gson = new GsonBuilder().setPrettyPrinting().setLenient().create();
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            privacyIDEA.error(e.getMessage());
            return json;
        }

        return gson.toJson(obj);
    }

    /**
     * Extract the auth token from the response of the server.
     *
     * @param serverResponse response of the server
     * @return the auth token or null if error
     */
    String extractAuthToken(String serverResponse)
    {
        if (serverResponse != null && !serverResponse.isEmpty())
        {
            JsonElement root = JsonParser.parseString(serverResponse);
            if (root != null)
            {
                try
                {
                    JsonObject obj = root.getAsJsonObject();
                    return obj.getAsJsonObject(RESULT).getAsJsonObject(VALUE).getAsJsonPrimitive(TOKEN).getAsString();
                }
                catch (Exception e)
                {
                    privacyIDEA.error("Response did not contain an authorization token: " + formatJson(serverResponse));
                }
            }
        }
        else
        {
            privacyIDEA.error("/auth response was empty or null!");
        }
        return null;
    }

    /**
     * Parse the response of the server into a PIResponse object.
     *
     * @param serverResponse response of the server
     * @return PIResponse or null if input is empty
     */
    public PIResponse parsePIResponse(String serverResponse)
    {
        if (serverResponse == null || serverResponse.isEmpty())
        {
            return null;
        }

        PIResponse response = new PIResponse();
        response.rawMessage = serverResponse;

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            privacyIDEA.error(e);
            return response;
        }

        response.id = getInt(obj, ID);
        response.piVersion = getString(obj, VERSION_NUMBER);
        response.signature = getString(obj, SIGNATURE);
        response.jsonRPCVersion = getString(obj, JSONRPC);

        JsonObject result = obj.getAsJsonObject(RESULT);
        if (result != null)
        {
            String r = getString(result, AUTHENTICATION);
            for (AuthenticationStatus as: AuthenticationStatus.values())
            {
                if (as.toString().equals(r))
                {
                    response.authentication = as;
                }
            }
            response.status = getBoolean(result, STATUS);
            response.value = getBoolean(result, VALUE);

            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull())
            {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                response.error = new PIError(getInt(errObj, CODE), getString(errObj, MESSAGE));
                return response;
            }
        }

        JsonElement detailElem = obj.get(DETAIL);
        if (detailElem != null && !detailElem.isJsonNull())
        {
            JsonObject detail = obj.getAsJsonObject(DETAIL);

            // Translate some preferred client mode names
            String modeFromResponse = getString(detail, PREFERRED_CLIENT_MODE);
            if ("poll".equals(modeFromResponse))
            {
                response.preferredClientMode = "push";
            }
            else if ("interactive".equals(modeFromResponse))
            {
                response.preferredClientMode = "otp";
            }
            else
            {
                response.preferredClientMode = modeFromResponse;
            }
            response.message = getString(detail, MESSAGE);
            response.image = getString(detail, IMAGE);
            response.serial = getString(detail, SERIAL);
            response.transactionID = getString(detail, TRANSACTION_ID);
            response.type = getString(detail, TYPE);
            response.otpLength = getInt(detail, OTPLEN);

            String r = getString(detail, CHALLENGE_STATUS);
            for (ChallengeStatus cs: ChallengeStatus.values())
            {
                if (cs.toString().equals(r))
                {
                    response.challengeStatus = cs;
                }
            }

            JsonArray arrMessages = detail.getAsJsonArray(MESSAGES);
            if (arrMessages != null)
            {
                arrMessages.forEach(val ->
                                        {
                                        if (val != null)
                                        {
                                            response.messages.add(val.getAsString());
                                        }
                                        });
            }

            JsonArray arrChallenges = detail.getAsJsonArray(MULTI_CHALLENGE);
            if (arrChallenges != null)
            {
                for (int i = 0; i < arrChallenges.size(); i++)
                {
                    JsonObject challenge = arrChallenges.get(i).getAsJsonObject();
                    String serial = getString(challenge, SERIAL);
                    String message = getString(challenge, MESSAGE);
                    String clientMode = getString(challenge, CLIENT_MODE);
                    String image = getString(challenge, IMAGE);
                    String transactionID = getString(challenge, TRANSACTION_ID);
                    String type = getString(challenge, TYPE);

                    if (TOKEN_TYPE_WEBAUTHN.equals(type))
                    {
                        String webauthnSignRequest = getItemFromAttributes(WEBAUTHN_SIGN_REQUEST, challenge);
                        response.multiChallenge.add(new WebAuthn(serial, message, clientMode, image, transactionID, webauthnSignRequest));
                    }
                    else
                    {
                        response.multiChallenge.add(new Challenge(serial, message, clientMode, image, transactionID, type));
                    }
                }
            }
        }
        return response;
    }

    static String mergeWebAuthnSignRequest(WebAuthn webauthn, List<String> arr) throws JsonSyntaxException
    {
        List<JsonArray> extracted = new ArrayList<>();
        for (String signRequest : arr)
        {
            JsonObject obj = JsonParser.parseString(signRequest).getAsJsonObject();
            extracted.add(obj.getAsJsonArray("allowCredentials"));
        }

        JsonObject signRequest = JsonParser.parseString(webauthn.signRequest()).getAsJsonObject();
        JsonArray allowCredentials = new JsonArray();
        extracted.forEach(allowCredentials::addAll);

        signRequest.add("allowCredentials", allowCredentials);

        return signRequest.toString();
    }

    private String getItemFromAttributes(String item, JsonObject jsonObject)
    {
        String ret = "";
        JsonElement attributeElement = jsonObject.get(ATTRIBUTES);
        if (attributeElement != null && !attributeElement.isJsonNull())
        {
            JsonElement requestElement = attributeElement.getAsJsonObject().get(item);
            if (requestElement != null && !requestElement.isJsonNull())
            {
                ret = requestElement.toString();
            }
        }
        return ret;
    }

    /**
     * Parse the response of the /token endpoint into a list of objects.
     *
     * @param serverResponse response of the server.
     * @return list of token info objects or null
     */
    List<TokenInfo> parseTokenInfoList(String serverResponse)
    {
        if (serverResponse == null || serverResponse.isEmpty())
        {
            return null;
        }

        List<TokenInfo> ret = new ArrayList<>();
        JsonObject object;
        try
        {
            object = JsonParser.parseString(serverResponse).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            privacyIDEA.error(e);
            return ret;
        }

        JsonObject result = object.getAsJsonObject(RESULT);
        if (result != null)
        {
            JsonObject value = result.getAsJsonObject(VALUE);

            if (value != null)
            {
                JsonArray tokens = value.getAsJsonArray(TOKENS);
                if (tokens != null)
                {
                    List<TokenInfo> infos = new ArrayList<>();
                    tokens.forEach(jsonValue -> infos.add(parseSingleTokenInfo(jsonValue.toString())));
                    ret = infos;
                }
            }
        }
        return ret;
    }

    /**
     * Parse the info of a single token into an object.
     *
     * @param json json array element as string
     * @return TokenInfo object, might be null object is json is empty
     */
    private TokenInfo parseSingleTokenInfo(String json)
    {
        TokenInfo info = new TokenInfo();
        if (json == null || json.isEmpty())
        {
            return info;
        }

        info.rawJson = json;

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
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
        info.image = getString(obj, IMAGE);
        info.syncWindow = getInt(obj, "sync_window");
        info.tokenType = getString(obj, "tokentype");
        info.userEditable = getBoolean(obj, "user_editable");
        info.userID = getString(obj, "user_id");
        info.userRealm = getString(obj, "user_realm");
        info.username = getString(obj, USERNAME);

        JsonObject joInfo = obj.getAsJsonObject(INFO);
        if (joInfo != null)
        {
            joInfo.entrySet().forEach(entry ->
                                          {
                                          if (entry.getKey() != null && entry.getValue() != null)
                                          {
                                              info.info.put(entry.getKey(), entry.getValue().getAsString());
                                          }
                                          });
        }

        JsonArray arrRealms = obj.getAsJsonArray(REALMS);
        if (arrRealms != null)
        {
            arrRealms.forEach(val ->
                                  {
                                  if (val != null)
                                  {
                                      info.realms.add(val.getAsString());
                                  }
                                  });
        }
        return info;
    }

    /**
     * Parse the response of /token/init into an object.
     *
     * @param serverResponse response of /token/init
     * @return RolloutInfo object, might be null object if response is empty
     */
    RolloutInfo parseRolloutInfo(String serverResponse)
    {
        RolloutInfo rInfo = new RolloutInfo();
        rInfo.raw = serverResponse;
        rInfo.googleurl = new RolloutInfo.GoogleURL();
        rInfo.oathurl = new RolloutInfo.OATHURL();
        rInfo.otpkey = new RolloutInfo.OTPKey();

        if (serverResponse == null || serverResponse.isEmpty())
        {
            return rInfo;
        }

        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(serverResponse).getAsJsonObject();

            JsonObject result = obj.getAsJsonObject(RESULT);
            JsonElement errElem = result.get(ERROR);
            if (errElem != null && !errElem.isJsonNull())
            {
                JsonObject errObj = result.getAsJsonObject(ERROR);
                rInfo.error = new PIError(getInt(errObj, CODE), getString(errObj, MESSAGE));
                return rInfo;
            }

            JsonObject detail = obj.getAsJsonObject("detail");
            if (detail != null)
            {
                JsonObject google = detail.getAsJsonObject("googleurl");
                if (google != null)
                {
                    rInfo.googleurl.description = getString(google, "description");
                    rInfo.googleurl.img = getString(google, "img");
                    rInfo.googleurl.value = getString(google, "value");
                }

                JsonObject oath = detail.getAsJsonObject("oath");
                if (oath != null)
                {
                    rInfo.oathurl.description = getString(oath, "description");
                    rInfo.oathurl.img = getString(oath, "img");
                    rInfo.oathurl.value = getString(oath, "value");
                }

                JsonObject otp = detail.getAsJsonObject("otpkey");
                if (otp != null)
                {
                    rInfo.otpkey.description = getString(otp, "description");
                    rInfo.otpkey.img = getString(otp, "img");
                    rInfo.otpkey.value = getString(otp, "value");
                    rInfo.otpkey.value_b32 = getString(otp, "value_b32");
                }

                rInfo.serial = getString(detail, "serial");
                rInfo.rolloutState = getString(detail, "rollout_state");
            }
        }
        catch (JsonSyntaxException | ClassCastException e)
        {
            privacyIDEA.error(e);
            return rInfo;
        }

        return rInfo;
    }

    /**
     * Parse the json string that is returned from the browser after signing the WebAuthnSignRequest into a map.
     * The map contains the parameters with the corresponding keys ready to be sent to the server.
     *
     * @param json json string from the browser
     * @return map
     */
    Map<String, String> parseWebAuthnSignResponse(String json)
    {
        Map<String, String> params = new LinkedHashMap<>();
        JsonObject obj;
        try
        {
            obj = JsonParser.parseString(json).getAsJsonObject();
        }
        catch (JsonSyntaxException e)
        {
            privacyIDEA.error("WebAuthn sign response has the wrong format: " + e.getLocalizedMessage());
            return null;
        }

        params.put(CREDENTIALID, getString(obj, CREDENTIALID));
        params.put(CLIENTDATA, getString(obj, CLIENTDATA));
        params.put(SIGNATUREDATA, getString(obj, SIGNATUREDATA));
        params.put(AUTHENTICATORDATA, getString(obj, AUTHENTICATORDATA));

        // The userhandle and assertionclientextension fields are optional
        String userhandle = getString(obj, USERHANDLE);
        if (!userhandle.isEmpty())
        {
            params.put(USERHANDLE, userhandle);
        }
        String extensions = getString(obj, ASSERTIONCLIENTEXTENSIONS);
        if (!extensions.isEmpty())
        {
            params.put(ASSERTIONCLIENTEXTENSIONS, extensions);
        }
        return params;
    }

    private boolean getBoolean(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isBoolean() && primitive.getAsBoolean();
    }

    private int getInt(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isNumber() ? primitive.getAsInt() : 0;
    }

    private String getString(JsonObject obj, String name)
    {
        JsonPrimitive primitive = getPrimitiveOrNull(obj, name);
        return primitive != null && primitive.isString() ? primitive.getAsString() : "";
    }

    private JsonPrimitive getPrimitiveOrNull(JsonObject obj, String name)
    {
        JsonPrimitive primitive = null;
        try
        {
            primitive = obj.getAsJsonPrimitive(name);
        }
        catch (Exception e)
        {
            // Just catch the exception instead of checking to get some log
            privacyIDEA.error("Cannot get " + name + " from JSON");
            privacyIDEA.error(e);
        }
        return primitive;
    }
}
