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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;

import static org.junit.Assert.assertNull;

public class TestErrors implements IPILogger
{
    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;
    private final String username = "Test";

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        String realm = "realm";

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").simpleLogger(null).realm(realm).sslVerify(false).logger(this).build();
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }

    @Test
    public void test()
    {
        log("testLog");
        error("testError");

        String authToken = privacyIDEA.getAuthToken();

        assertNull(authToken);
    }

    @Override
    public void log(String message) {
        System.out.println(message);
    }

    @Override
    public void error(String message) {
        System.err.println(message);
    }

    @Override
    public void log(Throwable t) {
        System.out.println(t.getMessage());
    }

    @Override
    public void error(Throwable t) {
        System.err.println(t.getMessage());
    }
}
