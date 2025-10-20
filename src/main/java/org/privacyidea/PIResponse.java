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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.PIConstants.CONTAINER_TYPE_SMARTPHONE;


/**
 * This class parses the JSON response of privacyIDEA into a POJO for easier access.
 */
public class PIResponse
{
    public String message = "";
    public String preferredClientMode = "";
    public List<String> messages = new ArrayList<>();
    public List<Challenge> multiChallenge = new ArrayList<>();
    public String transactionID = "";
    public String serial = "";
    public ChallengeStatus challengeStatus = ChallengeStatus.none;
    public String image = "";
    public int id = 0;
    public String jsonRPCVersion = "";
    public boolean status = false;
    public boolean value = false;
    public AuthenticationStatus authentication = AuthenticationStatus.NONE;
    public String piVersion = ""; // e.g. 3.2.1
    public String rawMessage = "";
    public String signature = "";
    public String type = ""; // Type of token that was matching the request
    public int otpLength = 0;
    public PIError error = null;
    // Passkey content is json string and can be passed to the browser as is
    public String passkeyChallenge = "";
    public String passkeyRegistration = "";
    public String passkeyMessage = "";
    public String username = "";
    public String enrollmentLink = "";
    // Enroll via Multichallenge
    public boolean isEnrollViaMultichallenge = false;
    public boolean isEnrollViaMultichallengeOptional = false;

    public String webAuthnSignRequest = "";
    public String webAuthnTransactionId = "";

    public boolean authenticationSuccessful()
    {
        if (authentication == AuthenticationStatus.ACCEPT && (multiChallenge == null || multiChallenge.isEmpty()))
        {
            return true;
        }
        else
        {
            return value && (multiChallenge == null || multiChallenge.isEmpty());
        }
    }

    /**
     * Check if a PUSH token was triggered.
     *
     * @return True if a PUSH token was triggered.
     */
    public boolean pushAvailable()
    {
        return multiChallenge.stream().anyMatch(c -> isPushOrSmartphoneContainer(c.getType()));
    }

    private boolean isPushOrSmartphoneContainer(String type) {
        return TOKEN_TYPE_PUSH.equals(type) || CONTAINER_TYPE_SMARTPHONE.equals(type);
    }

    /**
     * Get the messages of all triggered PUSH challenges.
     *
     * @return Combined messages of all PUSH challenges.
     */
    public String pushMessage()
    {
        return reduceChallengeMessagesWhere(c -> isPushOrSmartphoneContainer(c.getType()));
    }

    public String otpTransactionId()
    {
        for (Challenge challenge : multiChallenge)
        {
            if (!isPushOrSmartphoneContainer(challenge.getType()) && !TOKEN_TYPE_WEBAUTHN.equals(challenge.getType()))
            {
                return challenge.transactionID;
            }
        }
        return null;
    }

    public String pushTransactionId() {
        for (Challenge challenge : multiChallenge)
        {
            if (isPushOrSmartphoneContainer(challenge.getType()))
            {
                return challenge.transactionID;
            }
        }
        return null;
    }

    public boolean hasChallenges()
    {
        return (multiChallenge != null && !multiChallenge.isEmpty()) ||
               isNotBlank(mergedSignRequest()) ||
               isNotBlank(passkeyChallenge);
    }

    private boolean isNotBlank(String str) {
        return str != null && !str.trim().isEmpty();
    }

    /**
     * Get the messages of all token that require an input field (HOTP, TOTP, SMS, Email...) reduced to a single string.
     *
     * @return Message string.
     */
    public String otpMessage()
    {
        return reduceChallengeMessagesWhere(c -> !(isPushOrSmartphoneContainer(c.getType())));
    }

    private String reduceChallengeMessagesWhere(Predicate<Challenge> predicate)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(
                multiChallenge.stream().filter(predicate).map(Challenge::getMessage).distinct().reduce("", (a, s) -> a + s + ", ").trim());

        if (sb.length() > 0)
        {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    /**
     * @return List of token types that were triggered or an empty list.
     */
    public List<String> triggeredTokenTypes()
    {
        List<String> types = multiChallenge.stream().map(Challenge::getType).distinct().collect(Collectors.toList());
        if (this.webAuthnSignRequest != null && !this.webAuthnSignRequest.isEmpty())
        {
            types.add(TOKEN_TYPE_WEBAUTHN);
        }
        return types;
    }

    /**
     * Return the SignRequest that contains the merged allowCredentials so that the SignRequest can be used with any device that
     * is allowed to answer the SignRequest.
     * <p>
     * Can return an empty string if an error occurred or if no WebAuthn challenges have been triggered.
     *
     * @return Merged SignRequest or empty string.
     */
    public String mergedSignRequest()
    {
        if (this.webAuthnSignRequest == null || this.webAuthnSignRequest.isEmpty())
        {
            return "";
        }
        return this.webAuthnSignRequest;
    }

    public String toJSON()
    {
        GsonBuilder builder = new GsonBuilder();
        builder.setPrettyPrinting();
        Gson gson = builder.create();
        return gson.toJson(this);
    }

    public static PIResponse fromJSON(String json)
    {
        return new Gson().fromJson(json, PIResponse.class);
    }

    @Override
    public String toString()
    {
        return rawMessage;
    }
}