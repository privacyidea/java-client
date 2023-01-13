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
    private final String client_mode;
    private final String message;
    private final String transaction_id;
    private final String type;
    private final String image;

    public Challenge(String serial, String message, String client_mode, String image, String transaction_id, String type)
    {
        this.serial = serial;
        this.message = message;
        this.client_mode = client_mode;
        this.image = image;
        this.transaction_id = transaction_id;
        this.type = type;
    }

    public List<String> getAttributes()
    {
        return attributes;
    }

    public String getSerial()
    {
        return serial;
    }

    public String getMessage()
    {
        return message;
    }
    public String getClientMode() { return client_mode; }

    public String getImage() { return image.replaceAll("\"", ""); }

    public String getTransactionID()
    {
        return transaction_id;
    }

    public String getType()
    {
        return type;
    }
}
