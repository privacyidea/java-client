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

import com.google.gson.JsonSyntaxException;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;

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
    public String username = "";

    public boolean authenticationSuccessful()
    {
        if (authentication == AuthenticationStatus.ACCEPT)
        {
            return true;
        }
        else
        {
            return value && authentication != AuthenticationStatus.CHALLENGE;
        }
    }

    /**
     * Check if a PUSH token was triggered.
     *
     * @return True if a PUSH token was triggered.
     */
    public boolean pushAvailable()
    {
        return multiChallenge.stream().anyMatch(c -> TOKEN_TYPE_PUSH.equals(c.getType()));
    }

    /**
     * Get the messages of all triggered PUSH challenges.
     *
     * @return Combined messages of all PUSH challenges.
     */
    public String pushMessage()
    {
        return reduceChallengeMessagesWhere(c -> TOKEN_TYPE_PUSH.equals(c.getType()));
    }

    /**
     * Get the messages of all token that require an input field (HOTP, TOTP, SMS, Email...) reduced to a single string.
     *
     * @return Message string.
     */
    public String otpMessage()
    {
        return reduceChallengeMessagesWhere(c -> !(TOKEN_TYPE_PUSH.equals(c.getType())));
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
        return multiChallenge.stream().map(Challenge::getType).distinct().collect(Collectors.toList());
    }

    /**
     * Get all WebAuthn challenges from the multi_challenge.
     *
     * @return List of WebAuthn objects or empty list
     */
    public List<WebAuthn> webAuthnSignRequests()
    {
        List<WebAuthn> ret = new ArrayList<>();
        multiChallenge.stream().filter(c -> TOKEN_TYPE_WEBAUTHN.equals(c.getType())).collect(Collectors.toList()).forEach(c ->
                                                                                                                          {
                                                                                                                              if (c instanceof WebAuthn)
                                                                                                                              {
                                                                                                                                  ret.add((WebAuthn) c);
                                                                                                                              }
                                                                                                                          });
        return ret;
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
        List<WebAuthn> webauthnSignRequests = webAuthnSignRequests();
        if (webauthnSignRequests.isEmpty())
        {
            return "";
        }
        if (webauthnSignRequests.size() == 1)
        {
            return webauthnSignRequests.get(0).signRequest();
        }

        WebAuthn webauthn = webauthnSignRequests.get(0);
        List<String> stringSignRequests = webauthnSignRequests.stream().map(WebAuthn::signRequest).collect(Collectors.toList());

        try
        {
            return JSONParser.mergeWebAuthnSignRequest(webauthn, stringSignRequests);
        }
        catch (JsonSyntaxException e)
        {
            return "";
        }
    }

    @Override
    public String toString()
    {
        return rawMessage;
    }
}