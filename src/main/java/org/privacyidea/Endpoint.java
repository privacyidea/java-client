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
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.internal.connection.RealCall;

import static org.privacyidea.PIConstants.GET;
import static org.privacyidea.PIConstants.HEADER_USER_AGENT;
import static org.privacyidea.PIConstants.POST;
import static org.privacyidea.PIConstants.WEBAUTHN_PARAMETERS;

/**
 * This class handles sending requests to the server.
 */
class Endpoint
{
    private final PrivacyIDEA privacyIDEA;
    private final PIConfig piconfig;
    private final OkHttpClient client;

    final TrustManager[] trustAllManager = new TrustManager[]{new X509TrustManager()
    {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
        {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
        {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers()
        {
            return new java.security.cert.X509Certificate[]{};
        }
    }};

    Endpoint(PrivacyIDEA privacyIDEA)
    {
        this.privacyIDEA = privacyIDEA;
        this.piconfig = privacyIDEA.configuration();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        if (!this.piconfig.doSSLVerify)
        {
            // Trust all certs and verify every host
            try
            {
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllManager, new java.security.SecureRandom());
                final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllManager[0]);
                builder.hostnameVerifier((s, sslSession) -> true);
            }
            catch (KeyManagementException | NoSuchAlgorithmException e)
            {
                privacyIDEA.error(e);
            }
        }
        this.client = builder.build();
    }

    /**
     * Add a request to the okhttp queue. The callback will be invoked upon success or failure.
     *
     * @param endpoint server endpoint
     * @param params   request parameters
     * @param headers  request headers
     * @param method   http request method
     * @param callback okhttp3 callback
     */
    void sendRequestAsync(String endpoint, Map<String, String> params, Map<String, String> headers, String method,
                          Callback callback)
    {
        HttpUrl httpUrl = HttpUrl.parse(piconfig.serverURL + endpoint);
        if (httpUrl == null)
        {
            privacyIDEA.error("Server url could not be parsed: " + (piconfig.serverURL + endpoint));
            // Invoke the callback to terminate the thread that called this method.
            callback.onFailure(null,
                               new IOException("Request could not be created because the url could not be parsed"));
            return;
        }
        HttpUrl.Builder urlBuilder = httpUrl.newBuilder();
        privacyIDEA.log(method + " " + endpoint);
        params.forEach((k, v) ->
                       {
                           if (k.equals("pass") || k.equals("password"))
                           {
                               StringBuilder tmp = new StringBuilder();
                               for (int i = 0; i < v.length(); i++)
                               {
                                   tmp.append("*");
                               }
                               v = tmp.toString();
                           }

                           privacyIDEA.log(k + "=" + v);
                       });

        if (GET.equals(method))
        {
            params.forEach((key, value) ->
                           {
                               try
                               {
                                   String encValue = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                                   urlBuilder.addQueryParameter(key, encValue);
                               }
                               catch (UnsupportedEncodingException e)
                               {
                                   e.printStackTrace();
                               }
                           });
        }

        String url = urlBuilder.build().toString();
        //privacyIDEA.log("URL: " + url);
        Request.Builder requestBuilder = new Request.Builder().url(url);

        // Add the headers
        requestBuilder.addHeader(HEADER_USER_AGENT, piconfig.userAgent);
        if (headers != null && !headers.isEmpty())
        {
            headers.forEach(requestBuilder::addHeader);
        }

        if (POST.equals(method))
        {
            FormBody.Builder formBodyBuilder = new FormBody.Builder();
            params.forEach((key, value) ->
                           {
                               if (key != null && value != null)
                               {
                                   String encValue = value;
                                   // WebAuthn params are excluded from url encoding,
                                   // they are already in the correct encoding for the server
                                   if (!WEBAUTHN_PARAMETERS.contains(key))
                                   {
                                       try
                                       {
                                           encValue = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
                                       }
                                       catch (UnsupportedEncodingException e)
                                       {
                                           privacyIDEA.error(e);
                                       }
                                   }
                                   formBodyBuilder.add(key, encValue);
                               }
                           });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        Request request = requestBuilder.build();
        //privacyIDEA.log("HEADERS:\n" + request.headers().toString());
        client.newCall(request).enqueue(callback);
    }
}