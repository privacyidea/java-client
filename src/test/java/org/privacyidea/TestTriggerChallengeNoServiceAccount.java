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
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class TestTriggerChallengeNoServiceAccount implements IPILogger {

    private ClientAndServer mockServer;
    private PrivacyIDEA privacyIDEA;

    @Before
    public void setup() {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test")
                .sslVerify(false)
                .logger(this)
                .build();
    }

    @Test
    public void testTriggerChallenge() {
        String username = "testuser";
        PIResponse responseTriggerChallenge = privacyIDEA.triggerChallenges(username);

        assertNull(responseTriggerChallenge);
    }

    @After
    public void tearDown() {
        mockServer.stop();
    }

    @Override
    public void error(String message) {
        System.err.println(message);
    }

    @Override
    public void log(String message) {
        System.out.println(message);
    }

    @Override
    public void error(Throwable t) {
        t.printStackTrace();
    }

    @Override
    public void log(Throwable t) {
        t.printStackTrace();
    }
}