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

public class Challenge
{
    private final List<String> attributes = new ArrayList<>();
    private final String serial;
    private final String clientMode;
    private final String message;
    private final String transactionId;
    private final String type;
    private final String image;

    public Challenge(String serial, String message, String clientMode, String image, String transactionId, String type)
    {
        this.serial = serial;
        this.message = message;
        this.clientMode = clientMode;
        this.image = image;
        this.transactionId = transactionId;
        this.type = type;
    }

    public List<String> getAttributes() { return attributes; }

    public String getSerial() { return serial; }

    public String getMessage() { return message; }

    public String getClientMode() { return clientMode; }

    public String getImage() { return image.replaceAll("\"", ""); }

    public String getTransactionID() { return transactionId; }

    public String getType() { return type; }
}
