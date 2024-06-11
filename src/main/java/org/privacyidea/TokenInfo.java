/*
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class TokenInfo
{
    public boolean active = false;
    public int count = 0;
    public int countWindow = 0;
    public String description = "";
    public int failCount = 0;
    public int id = 0;
    public final Map<String, String> info = new HashMap<>();
    public boolean locked = false;
    public int maxFail = 0;
    public int otpLen = 0;
    public final List<String> realms = new ArrayList<>();
    public String resolver = "";
    public boolean revoked = false;
    public String rolloutState = "";
    public String serial = "";
    public String image = "";
    public int syncWindow = 0;
    public String tokenType = "";
    public boolean userEditable = false;
    public String userID = "";
    public String userRealm = "";
    public String username = "";
    public String rawJson = "";
}
