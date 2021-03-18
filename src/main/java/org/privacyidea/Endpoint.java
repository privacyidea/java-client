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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static org.privacyidea.PIConstants.GET;
import static org.privacyidea.PIConstants.HEADER_USER_AGENT;
import static org.privacyidea.PIConstants.POST;
import static org.privacyidea.PIConstants.WEBAUTHN_PARAMETERS;

/**
 * This class handles sending requests to the server.
 */
class Endpoint {

    private final PrivacyIDEA privacyIDEA;
    private List<String> logExcludedEndpointPrints = Arrays.asList(PIConstants.ENDPOINT_AUTH, PIConstants.ENDPOINT_POLLTRANSACTION); //Collections.emptyList(); //
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
        this.piconfig = privacyIDEA.configuration();

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

    void sendRequestAsync(String endpoint, Map<String, String> params, Map<String, String> headers, String method, Callback callback) {
        Request request = prepareRequest(endpoint, params, headers, method);
        //privacyIDEA.log("HEADERS:\n" + request.headers().toString());
        if (request!= null) {
            client.newCall(request).enqueue(callback);
        } else {
            // Invoke the callback to stop the thread that called this
            callback.onFailure(null, new IOException("Request could not be created!"));
        }
    }

    String sendRequest(String endpoint, Map<String, String> params, String method) {
        return sendRequest(endpoint, params, Collections.emptyMap(), method);
    }

    String sendRequest(String endpoint, Map<String, String> params, Map<String, String> headers, String method) {
        Request request = prepareRequest(endpoint, params, headers, method);
        if (request != null) {
            try {
                Response response = client.newCall(request).execute();
                if (response.body() != null) {
                    String ret = response.body().string();
                    if (!logExcludedEndpointPrints.contains(endpoint)) {
                        privacyIDEA.log(privacyIDEA.parser.formatJson(ret));
                    }
                    return ret;
                } else {
                    privacyIDEA.log("Response body is null.");
                }
            } catch (IOException e) {
                privacyIDEA.error(e);
            }
        }

        return "";
    }

    private Request prepareRequest(String endpoint, Map<String, String> params, Map<String, String> headers, String method) {
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
                    String encValue = value;
                    encValue = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                    urlBuilder.addQueryParameter(key, encValue);
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            });
        }

        String url = urlBuilder.build().toString();
        //privacyIDEA.log("using URL: " + url);
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);

        // Add the headers
        requestBuilder.addHeader(HEADER_USER_AGENT, piconfig.userAgent);
        if (headers != null && !headers.isEmpty()) {
            headers.forEach(requestBuilder::addHeader);
        }

        if (POST.equals(method)) {
            FormBody.Builder formBodyBuilder = new FormBody.Builder();
            params.forEach((key, value) -> {
                if (key != null && value != null) {
                    String encValue = value;
                    // WebAuthn params are excluded from url encoded, they are already in the correct format for the server
                    if (!WEBAUTHN_PARAMETERS.contains(key)) {
                        try {
                            encValue = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                        } catch (UnsupportedEncodingException e) {
                            privacyIDEA.error(e);
                        }
                    }
                    //privacyIDEA.log("" + key + "=" + encValue);
                    formBodyBuilder.add(key, encValue);
                }
            });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        return requestBuilder.build();
    }

    public List<String> logExcludedEndpoints() {
        return logExcludedEndpointPrints;
    }

    public void logExcludedEndpoints(List<String> list) {
        logExcludedEndpointPrints = list;
    }
}
