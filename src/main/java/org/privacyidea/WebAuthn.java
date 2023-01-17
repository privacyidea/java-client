/**
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

public class WebAuthn extends Challenge
{
    private final String signRequest;

    public WebAuthn(String serial, String message, String client_mode, String image, String transaction_id,
                    String signRequest)
    {
        super(serial, message, client_mode, image, transaction_id, PIConstants.TOKEN_TYPE_WEBAUTHN);
        this.signRequest = signRequest;
    }

    /**
     * Returns the WebAuthnSignRequest in JSON format as a string, ready to use with pi-webauthn.js.
     * If this returns an empty string, it *might* indicate that the PIN of this token should be changed.
     *
     * @return sign request or empty string
     */
    public String signRequest()
    {
        return signRequest;
    }
}
