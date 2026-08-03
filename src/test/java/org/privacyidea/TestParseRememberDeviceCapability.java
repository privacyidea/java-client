/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests for {@link JSONParser#parseRememberDeviceCapability(String)} — the /validate/capabilities parse.
 * The capability lives at result.value.capabilities.remember_device (the JSON-RPC envelope); a top-level
 * lookup was a false negative that suppressed the remember-device checkbox. Tri-state: TRUE/FALSE for a
 * real privacyIDEA response, null when the body is not privacyIDEA JSON (so the caller retries).
 */
public class TestParseRememberDeviceCapability
{
    private PrivacyIDEA privacyIDEA;
    private JSONParser parser;

    @Before
    public void setup()
    {
        privacyIDEA = PrivacyIDEA.newBuilder("https://localhost", "test").build();
        parser = privacyIDEA.parser;
    }

    @After
    public void teardown() throws Exception
    {
        privacyIDEA.close();
    }

    @Test
    public void capabilityTrue()
    {
        String body = "{\"result\":{\"status\":true,\"value\":{\"capabilities\":{\"remember_device\":true}}}}";
        assertEquals(Boolean.TRUE, parser.parseRememberDeviceCapability(body));
    }

    @Test
    public void capabilityFalse()
    {
        String body = "{\"result\":{\"status\":true,\"value\":{\"capabilities\":{\"remember_device\":false}}}}";
        assertEquals(Boolean.FALSE, parser.parseRememberDeviceCapability(body));
    }

    @Test
    public void validResponseWithoutCapabilityIsFalse()
    {
        // e.g. a 401 for an unidentified client: valid privacyIDEA JSON, but no capabilities present.
        String body = "{\"result\":{\"status\":false,\"error\":{\"code\":4031,\"message\":\"Invalid API key\"}}}";
        assertEquals(Boolean.FALSE, parser.parseRememberDeviceCapability(body));
    }

    @Test
    public void nonPrivacyIdeaBodyIsNull()
    {
        // e.g. an old server's 404 HTML page — unknown, so the caller retries rather than caches.
        assertNull(parser.parseRememberDeviceCapability("<html><body>404 Not Found</body></html>"));
    }

    @Test
    public void emptyBodyIsNull()
    {
        assertNull(parser.parseRememberDeviceCapability(""));
        assertNull(parser.parseRememberDeviceCapability(null));
    }
}
