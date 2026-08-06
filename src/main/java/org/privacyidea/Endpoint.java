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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import static org.privacyidea.PIConstants.GET;
import static org.privacyidea.PIConstants.HEADER_AUTHORIZATION;
import static org.privacyidea.PIConstants.HEADER_COOKIE;
import static org.privacyidea.PIConstants.HEADER_USER_AGENT;
import static org.privacyidea.PIConstants.HEADER_X_API_KEY;
import static org.privacyidea.PIConstants.POST;

/**
 * This class handles sending requests to the server.
 */
public class Endpoint
{
    private final PrivacyIDEA privacyIDEA;
    private final PIConfig piConfig;
    private final OkHttpClient client;

    // Request parameters whose values are secrets and must never be written to the log.
    private static final Set<String> SECRET_PARAMS = Set.of("pass", "password", "otpkey");

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
               .readTimeout(piConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               // Bound the whole call (all phases + retries) so it cannot outlive the configured timeout.
               .callTimeout(piConfig.httpTimeoutMs, TimeUnit.MILLISECONDS)
               // Do not follow redirects. This client talks to one explicitly-configured privacyIDEA URL and
               // has no reason to be redirected; following one could forward our custom sensitive headers
               // (X-API-Key, Cookie) to another host — OkHttp only auto-strips the standard Authorization
               // header on a cross-host redirect, not custom ones. A stray redirect should fail visibly.
               .followRedirects(false)
               .followSslRedirects(false);

        if (!this.piConfig.verifySSL)
        {
            // Disable certificate trust AND hostname verification. This is insecure (MITM-able) and only
            // intended for test setups — warn loudly so it is visible in the log if left on in production.
            privacyIDEA.error("verifySSL is disabled: TLS certificate and hostname verification are turned " +
                              "off. Do NOT use this in production.");
            try
            {
                final SSLContext sslContext = SSLContext.getInstance("TLS");
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
     * Send a request to the server and return the result synchronously (on the calling thread). OkHttp's own
     * connection pool handles concurrency; there is no extra thread pool, so the number of in-flight requests
     * is bounded only by the number of calling threads (i.e. the host IdP's request threads).
     *
     * @param endpoint server endpoint
     * @param params   request parameters
     * @param headers  request headers
     * @param method   http request method
     * @return the response body + Set-Cookie headers; body is null on a transport failure / bad URL
     */
    PIRequestResult sendRequest(String endpoint, Map<String, String> params, Map<String, String> headers, String method)
    {
        HttpUrl httpUrl = HttpUrl.parse(piConfig.serverURL + endpoint);
        if (httpUrl == null)
        {
            privacyIDEA.error("Server url could not be parsed: " + (piConfig.serverURL + endpoint));
            return new PIRequestResult(null, null);
        }
        HttpUrl.Builder urlBuilder = httpUrl.newBuilder();
        privacyIDEA.log(method + " " + endpoint);
        params.forEach((k, v) ->
                       {
                           // Redact secret values (fixed width, so the length is not disclosed) and strip
                           // control chars so a crafted value cannot forge extra log lines.
                           String logValue = SECRET_PARAMS.contains(k) ? "<hidden>" : sanitizeForLog(v);
                           privacyIDEA.log(sanitizeForLog(k) + "=" + logValue);
                       });

        if (GET.equals(method))
        {
            // Pass raw values to OkHttp, which percent-encodes them exactly once. (Do not pre-encode with
            // URLEncoder as well, or reserved characters get double-encoded and reach the server wrong.)
            params.forEach((key, value) ->
                           {
                               if (key != null && value != null)
                               {
                                   urlBuilder.addQueryParameter(key, value);
                               }
                           });
        }

        String url = urlBuilder.build().toString();
        //privacyIDEA.log("URL: " + url);
        Request.Builder requestBuilder = new Request.Builder().url(url);

        // Add the headers. A caller-supplied User-Agent (in the per-request headers) overrides the configured
        // default, so a single request can be marked as originating from a specific flow. Only add the default
        // when the caller did not provide one, to avoid sending two User-Agent headers.
        boolean callerProvidedUserAgent = headers != null &&
                                          headers.keySet().stream().anyMatch(h -> h.equalsIgnoreCase(HEADER_USER_AGENT));
        if (!callerProvidedUserAgent)
        {
            requestBuilder.addHeader(HEADER_USER_AGENT, piConfig.userAgent);
        }
        if (headers != null && !headers.isEmpty())
        {
            headers.forEach((k, v) ->
                            {
                                if (v == null)
                                {
                                    privacyIDEA.error("Unable to add header " + k + " because the value is null");
                                }
                                else
                                {
                                    requestBuilder.addHeader(k, v);
                                }
                            });
        }

        if (POST.equals(method))
        {
            FormBody.Builder formBodyBuilder = new FormBody.Builder();
            params.forEach((key, value) ->
                           {
                               if (key != null && value != null)
                               {
                                   // FormBody.add() percent-encodes the value exactly once, which is correct
                                   // for all params including WebAuthn (the server form-decodes it back to the
                                   // original). Pre-encoding with URLEncoder here would double-encode.
                                   formBodyBuilder.add(key, value);
                               }
                           });
            // This switches okhttp to make a post request
            requestBuilder.post(formBodyBuilder.build());
        }

        Request request = requestBuilder.build();
        // Log headers, but never the secret values (API key, session cookie).
        Headers reqHeaders = request.headers();
        StringBuilder headerLog = new StringBuilder("Header: ");
        for (int i = 0; i < reqHeaders.size(); i++)
        {
            String name = reqHeaders.name(i);
            String value = reqHeaders.value(i);
            if (HEADER_X_API_KEY.equalsIgnoreCase(name) || HEADER_COOKIE.equalsIgnoreCase(name)
                || HEADER_AUTHORIZATION.equalsIgnoreCase(name))
            {
                value = "<hidden>";
            }
            headerLog.append(name).append(": ").append(sanitizeForLog(value)).append(" | ");
        }
        privacyIDEA.log(headerLog.toString());

        // Execute synchronously on the calling thread. try-with-resources guarantees the response body is
        // closed on every path. The body is always read (even on non-2xx) because privacyIDEA returns its
        // JSON error envelope with 4xx/5xx status codes.
        try (Response response = client.newCall(request).execute())
        {
            List<String> setCookies = new ArrayList<>(response.headers("Set-Cookie"));
            ResponseBody responseBody = response.body();
            String body = responseBody == null ? null : responseBody.string();
            if (body != null
                && !privacyIDEA.logExcludedEndpoints().contains(endpoint)
                && !PIConstants.ENDPOINT_AUTH.equals(endpoint))
            {
                privacyIDEA.log(endpoint + " (" + response.code() + "):\n" + privacyIDEA.parser.formatJson(body));
            }
            return new PIRequestResult(body, setCookies);
        }
        catch (IOException e)
        {
            // Connection refused / timeout / TLS failure — surface as a null body (callers null-check).
            privacyIDEA.error(e);
            return new PIRequestResult(null, null);
        }
    }

    /**
     * Release the underlying OkHttp resources (dispatcher executor + pooled connections). Called from
     * {@link PrivacyIDEA#close()}.
     */
    void close()
    {
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
    }

    /**
     * Strip CR/LF (and other control chars) from a value before it is written to the log, so an
     * attacker-influenced value (e.g. a username) cannot inject forged log lines.
     */
    private static String sanitizeForLog(String value)
    {
        if (value == null)
        {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t\\p{Cntrl}]", " ");
    }
}