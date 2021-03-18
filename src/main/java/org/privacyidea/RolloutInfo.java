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

/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class RolloutInfo {

    public GoogleURL googleurl;
    public OATHURL oathurl;
    public OTPKey otpkey;
    public String raw;
    public String serial;
    public String rolloutState;

    public static class GoogleURL {
        public String description = "", img = "", value = "";
    }

    public static class OATHURL {
        public String description = "", img = "", value = "";
    }

    public static class OTPKey {
        public String description = "", img = "", value = "", value_b32 = "";
    }
}
