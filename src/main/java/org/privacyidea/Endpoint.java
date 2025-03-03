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

import okhttp3.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.privacyidea.PIConstants.*;

/**
 * This class handles sending requests to the server.
 */
class Endpoint
{
    private final PrivacyIDEA privacyIDEA;
    private final PIConfig piConfig;
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
        this.piConfig = privacyIDEA.configuration();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(piConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               .writeTimeout(piConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               .readTimeout(piConfig.httpTimeoutMs, TimeUnit.MILLISECONDS);

        if (!this.piConfig.verifySSL)
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

        if (!piConfig.proxyHost.isEmpty())
        {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(piConfig.proxyHost, piConfig.proxyPort));
            builder.proxy(proxy);
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
    void sendRequestAsync(String endpoint, Map<String, String> params, Map<String, String> headers, String method, Callback callback)
    {
        HttpUrl httpUrl = HttpUrl.parse(piConfig.serverURL + endpoint);
        if (httpUrl == null)
        {
            privacyIDEA.error("Server url could not be parsed: " + (piConfig.serverURL + endpoint));
            // Invoke the callback to terminate the thread that called this function.
            callback.onFailure(null, new IOException("Request could not be created because the url could not be parsed"));
            return;
        }
        HttpUrl.Builder urlBuilder = httpUrl.newBuilder();
        if (!piConfig.forwardClientIP.isEmpty())
        {
            privacyIDEA.log("Forwarding client IP: " + piConfig.forwardClientIP);
            params.put(CLIENT_IP, piConfig.forwardClientIP);
        }
        privacyIDEA.log(method + " " + endpoint);
        params.forEach((k, v) ->
                       {
                           if (k.equals("pass") || k.equals("password"))
                           {
                               v = "*".repeat(v.length());
                           }
                           privacyIDEA.log(k + "=" + v);
                       });

        if (GET.equals(method))
        {
            params.forEach((key, value) ->
                           {
                               String encValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
                               urlBuilder.addQueryParameter(key, encValue);
                           });
        }

        String url = urlBuilder.build().toString();
        //privacyIDEA.log("URL: " + url);
        Request.Builder requestBuilder = new Request.Builder().url(url);

        // Add the headers
        requestBuilder.addHeader(HEADER_USER_AGENT, piConfig.userAgent);
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
                                       encValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
                                   }
                                   formBodyBuilder.add(key, encValue);
                               }
                           });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        Request request = requestBuilder.build();
        //privacyIDEA.log("HEADERS:\n" + request.headers());
        client.newCall(request).enqueue(callback);
    }
}