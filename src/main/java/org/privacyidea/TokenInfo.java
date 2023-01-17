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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class TokenInfo
{
    boolean active = false;
    int count = 0;
    int countWindow = 0;
    String description = "";
    int failCount = 0;
    int id = 0;
    final Map<String, String> info = new HashMap<>();
    boolean locked = false;
    int maxFail = 0;
    int otpLen = 0;
    final List<String> realms = new ArrayList<>();
    String resolver = "";
    boolean revoked = false;
    String rolloutState = "";
    String serial = "";
    String image = "";
    int syncWindow = 0;
    String tokenType = "";
    boolean userEditable = false;
    String userID = "";
    String userRealm = "";
    String username = "";
    String rawJson = "";
}
