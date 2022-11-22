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
            if (privacyIDEA.serviceAccountInaccessible())
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
            String s = response.body().string();
            if (!privacyIDEA.logExcludedEndpoints().contains(path) && !ENDPOINT_AUTH.equals(path))
            {
                privacyIDEA.log(path + ":\n" + privacyIDEA.parser.formatJson(s));
            }
            callbackResult[0] = s;
        }
        latch.countDown();
    }
}