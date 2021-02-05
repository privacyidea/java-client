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

import java.util.ArrayList;
import java.util.List;

public class WebAuthn extends Challenge {

    private final List<String> attributes = new ArrayList<>();
    private final String signRequest;

    public WebAuthn(String serial, String message, String transaction_id, String signRequest) {
        super(serial, message, transaction_id, PIConstants.TOKEN_TYPE_WEBAUTHN);
        this.signRequest = signRequest;
    }

    public List<String> getAttributes() {
        return attributes;
    }


    public String getSignRequest() {
        return signRequest;
    }
}
