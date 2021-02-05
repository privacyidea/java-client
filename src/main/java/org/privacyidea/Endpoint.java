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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static org.privacyidea.PIConstants.ENDPOINT_AUTH;
import static org.privacyidea.PIConstants.GET;
import static org.privacyidea.PIConstants.HEADER_AUTHORIZATION;
import static org.privacyidea.PIConstants.HEADER_USER_AGENT;
import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.POST;
import static org.privacyidea.PIConstants.REALM;
import static org.privacyidea.PIConstants.RESULT;
import static org.privacyidea.PIConstants.TOKEN;
import static org.privacyidea.PIConstants.USERNAME;
import static org.privacyidea.PIConstants.VALUE;
import static org.privacyidea.PIConstants.WEBAUTHN_PARAMETERS;

/**
 * This class handles sending sending requests to the server.
 */
class Endpoint {

    private final PrivacyIDEA privacyIDEA;
    private List<String> logExcludedEndpointPrints = Collections.emptyList(); //Arrays.asList(PIConstants.ENDPOINT_AUTH, PIConstants.ENDPOINT_POLLTRANSACTION); //
    private final PIConfig piconfig;
    private final OkHttpClient client;

    final TrustManager[] trustAllManager = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{};
                }
            }
    };

    Endpoint(PrivacyIDEA privacyIDEA) {
        this.privacyIDEA = privacyIDEA;
        this.piconfig = privacyIDEA.getConfiguration();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        if (!this.piconfig.doSSLVerify) {
            // Trust all certs and verify every host
            try {
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllManager, new java.security.SecureRandom());
                final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllManager[0]);
                builder.hostnameVerifier((s, sslSession) -> true);
            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                privacyIDEA.error(e);
            }
        }
        this.client = builder.build();
    }

    String sendRequest(String endpoint, Map<String, String> params, boolean authTokenRequired, String method) {
        return sendRequest(endpoint, params, Collections.emptyMap(), authTokenRequired, method);
    }

    String sendRequest(String endpoint, Map<String, String> params, Map<String, String> headers, boolean authTokenRequired, String method) {
        HttpUrl httpUrl = HttpUrl.parse(piconfig.serverURL + endpoint);
        if (httpUrl == null) {
            privacyIDEA.error("Server url could not be parsed: " + (piconfig.serverURL + endpoint));
            return null;
        }
        HttpUrl.Builder urlBuilder = httpUrl.newBuilder();

        if (GET.equals(method)) {
            params.forEach((key, value) -> {
                //privacyIDEA.log("" + key + "=" + value);
                try {
                    String enc_value = value;
                    enc_value = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                    urlBuilder.addQueryParameter(key, enc_value);
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            });
        }

        String url = urlBuilder.build().toString();
        //privacyIDEA.log("using URL: " + url);
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);

        if (authTokenRequired) {
            String authToken = getAuthTokenFromServer();
            if (authToken.isEmpty()) {
                privacyIDEA.error("Failed to fetch authorization token from server!");
                return "";
            }
            requestBuilder.addHeader(HEADER_AUTHORIZATION, authToken);
        }

        // Add the headers
        requestBuilder.addHeader(HEADER_USER_AGENT, piconfig.userAgent);
        if (headers != null && !headers.isEmpty()) {
            headers.forEach(requestBuilder::addHeader);
        }

        if (POST.equals(method)) {
            FormBody.Builder formBodyBuilder = new FormBody.Builder();
            params.forEach((key, value) -> {
                if (key != null && value != null) {
                    String enc_value = value;
                    // WebAuthn params are excluded from url encoded, they are already in the correct format for the server
                    if (!WEBAUTHN_PARAMETERS.contains(key)) {
                        try {
                            enc_value = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                        } catch (UnsupportedEncodingException e) {
                            privacyIDEA.error(e);
                        }
                    }
                    //privacyIDEA.log("" + key + "=" + enc_value);
                    formBodyBuilder.add(key, enc_value);
                }
            });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        Request request = requestBuilder.build();
        //privacyIDEA.log("HEADERS:\n" + request.headers().toString());

        try {
            Response response = client.newCall(request).execute();
            if (response.body() != null) {
                String ret = response.body().string();
                endpointLog(endpoint, ret);
                return ret;
            } else {
                privacyIDEA.log("Response body is null.");
            }
        } catch (IOException e) {
            privacyIDEA.error(e);
        }

        return "";
    }

    String getAuthTokenFromServer() {
        if (!privacyIDEA.checkServiceAccountAvailable()) {
            privacyIDEA.log("Service account information not set, cannot retrieve auth token");
            return "";
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(USERNAME, piconfig.serviceAccountName);
        params.put(PASSWORD, piconfig.serviceAccountPass);

        if (piconfig.serviceAccountRealm != null && !piconfig.serviceAccountRealm.isEmpty()) {
            params.put(REALM, piconfig.serviceAccountRealm);
        } else if (piconfig.realm != null && !piconfig.realm.isEmpty()) {
            params.put(REALM, piconfig.realm);
        }

        String response = sendRequest(ENDPOINT_AUTH, params, false, POST);
        if (response != null && !response.isEmpty()) {
            JsonElement root = JsonParser.parseString(response);
            if (root != null) {
                JsonObject obj = root.getAsJsonObject();
                if (obj != null) {
                    return obj.getAsJsonObject(RESULT).getAsJsonObject(VALUE).getAsJsonPrimitive(TOKEN).getAsString();
                } else {
                    privacyIDEA.log("Response did not contain an authorization token: " + prettyFormatJson(response));
                }
            }
        } else {
            privacyIDEA.error("/auth response was empty or null!");
        }

        return "";
    }

    public static String prettyFormatJson(String json) {
        if (json == null || json.isEmpty()) return "";

        JsonObject obj;
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return json;
        }

        return gson.toJson(obj);
    }

    private void endpointLog(String endpoint, String response) {
        if (!logExcludedEndpointPrints.contains(endpoint)) {
            privacyIDEA.log(prettyFormatJson(response));
        }
    }

    public List<String> getLogExcludedEndpoints() {
        return logExcludedEndpointPrints;
    }

    public void setLogExcludedEndpoints(List<String> list) {
        logExcludedEndpointPrints = list;
    }
}
