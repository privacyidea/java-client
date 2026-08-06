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

import java.io.IOException;

import org.junit.Test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Lifecycle / builder contract tests: fail-fast construction, safe {@code getJWT()} without a service
 * account, and idempotent {@code close()}.
 */
public class TestClientLifecycle
{
    // L4 — a missing server URL must fail fast at build() instead of producing a half-built client.
    @Test
    public void buildRejectsNullServerUrl()
    {
        try
        {
            PrivacyIDEA.newBuilder(null, "test").build();
            fail("expected IllegalArgumentException for null serverURL");
        }
        catch (IllegalArgumentException expected)
        {
            // ok
        }
    }

    @Test
    public void buildRejectsEmptyUserAgent()
    {
        try
        {
            PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "  ").build();
            fail("expected IllegalArgumentException for blank userAgent");
        }
        catch (IllegalArgumentException expected)
        {
            // ok
        }
    }

    // getJWT() on a client without a service account must return null, not NPE on an uninitialised latch.
    @Test
    public void getJwtWithoutServiceAccountReturnsNull() throws IOException
    {
        try (PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                                  .verifySSL(false)
                                                  .logger(new PILogImplementation())
                                                  .build())
        {
            assertNull(privacyIDEA.getJWT());
        }
    }

    // close() must be safe to call twice.
    @Test
    public void closeIsIdempotent() throws IOException
    {
        PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                                             .verifySSL(false)
                                             .logger(new PILogImplementation())
                                             .build();
        privacyIDEA.close();
        privacyIDEA.close();
    }
}
