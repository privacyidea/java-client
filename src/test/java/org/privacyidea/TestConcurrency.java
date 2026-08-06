/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Proves the client executes many requests concurrently through one shared instance (the way an IdP uses it
 * during a login wave). With the old design a request occupied a bounded (20-thread) pool while the caller
 * also blocked, so N &gt; 20 requests serialized in rounds; the synchronous rewrite lets OkHttp's pool run
 * them all at once, bounded only by the caller threads.
 */
public class TestConcurrency
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    private static final int CONCURRENCY = 50;
    private static final int SERVER_DELAY_MS = 100;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);
        mockServer.when(HttpRequest.request().withMethod("POST").withPath("/validate/check"))
                  .respond(HttpResponse.response()
                                       .withContentType(MediaType.APPLICATION_JSON)
                                       .withBody(Utils.matchingOneToken())
                                       .withDelay(TimeUnit.MILLISECONDS, SERVER_DELAY_MS));

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                 .verifySSL(false)
                                 .logger(new PILogImplementation())
                                 .build();
    }

    @Test
    public void manyConcurrentRequestsRunInParallel() throws Exception
    {
        ExecutorService callers = Executors.newFixedThreadPool(CONCURRENCY);
        List<Callable<PIResponse>> tasks = new ArrayList<>();
        for (int i = 0; i < CONCURRENCY; i++)
        {
            tasks.add(() -> privacyIDEA.validateCheck("testuser", "123456"));
        }

        long start = System.currentTimeMillis();
        List<Future<PIResponse>> futures = callers.invokeAll(tasks, 30, TimeUnit.SECONDS);
        long elapsed = System.currentTimeMillis() - start;
        callers.shutdownNow();

        int ok = 0;
        for (Future<PIResponse> f : futures)
        {
            PIResponse r = f.get();
            assertNotNull("every concurrent request must get a response", r);
            assertTrue(r.value);
            ok++;
        }
        assertEquals(CONCURRENCY, ok);

        // Fully serialized would be ~CONCURRENCY * SERVER_DELAY_MS (= 5000ms). A generous ceiling well below
        // that proves the requests overlapped rather than running one-at-a-time.
        long serializedMs = (long) CONCURRENCY * SERVER_DELAY_MS;
        assertTrue("requests appear serialized (" + elapsed + "ms for " + CONCURRENCY + " calls)",
                   elapsed < serializedMs / 2);
    }

    @After
    public void tearDown()
    {
        mockServer.stop();
    }
}
