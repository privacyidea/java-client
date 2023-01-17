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
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import static org.privacyidea.PIConstants.ENDPOINT_AUTH;

/**
 * Instances of this class are submitted to the thread pool so that requests can be executed in parallel.
 */
public class AsyncRequestCallable implements Callable<String>, Callback
{
    private String path;
    private final String method;
    private final Map<String, String> headers;
    private final Map<String, String> params;
    private final boolean authTokenRequired;
    private final Endpoint endpoint;
    private final PrivacyIDEA privacyIDEA;
    final String[] callbackResult = {null};
    private CountDownLatch latch;

    public AsyncRequestCallable(PrivacyIDEA privacyIDEA, Endpoint endpoint, String path, Map<String, String> params,
                                Map<String, String> headers, boolean authTokenRequired, String method)
    {
        this.privacyIDEA = privacyIDEA;
        this.endpoint = endpoint;
        this.path = path;
        this.params = params;
        this.headers = headers;
        this.authTokenRequired = authTokenRequired;
        this.method = method;
    }

    @Override
    public String call() throws Exception
    {
        // If an auth token is required for the request, get that first then do the actual request
        if (this.authTokenRequired)
        {
            if (!privacyIDEA.serviceAccountAvailable())
            {
                privacyIDEA.error("Service account is required to retrieve auth token!");
                return null;
            }
            latch = new CountDownLatch(1);
            String tmpPath = path;
            path = ENDPOINT_AUTH;
            endpoint.sendRequestAsync(ENDPOINT_AUTH, privacyIDEA.serviceAccountParam(), Collections.emptyMap(),
                                      PIConstants.POST, this);
            latch.await();
            // Extract the auth token from the response
            String response = callbackResult[0];
            String authToken = privacyIDEA.parser.extractAuthToken(response);
            if (authToken == null)
            {
                // The parser already logs the error.
                return null;
            }
            // Add the auth token to the header
            headers.put(PIConstants.HEADER_AUTHORIZATION, authToken);
            path = tmpPath;
            callbackResult[0] = null;
        }

        // Do the actual request
        latch = new CountDownLatch(1);
        endpoint.sendRequestAsync(path, params, headers, method, this);
        latch.await();
        return callbackResult[0];
    }

    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e)
    {
        privacyIDEA.error(e);
        latch.countDown();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException
    {
        if (response.body() != null)
        {
            String s = response.body()
                               .string();
            if (!privacyIDEA.logExcludedEndpoints()
                            .contains(path) && !ENDPOINT_AUTH.equals(path))
            {
                privacyIDEA.log(path + ":\n" + privacyIDEA.parser.formatJson(s));
            }
            callbackResult[0] = s;
        }
        latch.countDown();
    }
}