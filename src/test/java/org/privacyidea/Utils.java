package org.privacyidea;

public class Utils
{
    private final static String authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU";

    public static String postAuthSuccessResponse()
    {
        return "{\n" + "    \"id\": 1,\n" +
               "    \"jsonrpc\": \"2.0\",\n" +
               "    \"result\": {\n" +
               "        \"status\": true,\n" +
               "        \"value\": {\n" +
               "            \"log_level\": 20,\n" +
               "            \"menus\": [\n" +
               "                \"components\",\n" +
               "                \"machines\"\n" +
               "            ],\n" +
               "            \"realm\": \"\",\n" +
               "            \"rights\": [\n" +
               "                \"policydelete\",\n" +
               "                \"resync\"\n" +
               "            ],\n" +
               "            \"role\": \"admin\",\n" +
               "            \"token\": \"" +
               authToken + "\",\n" +
               "            \"username\": \"admin\",\n" +
               "            \"logout_time\": 120,\n" +
               "            \"default_tokentype\": \"hotp\",\n" +
               "            \"user_details\": false,\n" +
               "            \"subscription_status\": 0\n" +
               "        }\n" + "    },\n" +
               "    \"time\": 1589446794.8502703,\n" +
               "    \"version\": \"privacyIDEA 3.2.1\",\n" +
               "    \"versionnumber\": \"3.2.1\",\n" +
               "    \"signature\": \"rsa_sha256_pss:\"\n" +
               "}";
    }

    public static String getTokenResponse()
    {
        return "{\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":{" +
               "\"count\":1," + "\"current\":1," + "\"tokens\":[{" + "\"active\":true," + "\"count\":2," +
               "\"count_window\":10," + "\"description\":\"\"," + "\"failcount\":0," + "\"id\":347," +
               "\"info\":{" + "\"count_auth\":\"1\"," + "\"count_auth_success\":\"1\"," +
               "\"hashlib\":\"sha1\"," + "\"last_auth\":\"2022-03-2912:18:59.639421+02:00\"," +
               "\"tokenkind\":\"software\"}," + "\"locked\":false," + "\"maxfail\":10," + "\"otplen\":6," +
               "\"realms\":[\"defrealm\"]," + "\"resolver\":\"deflocal\"," + "\"revoked\":false," +
               "\"rollout_state\":\"\"," + "\"serial\":\"OATH00123564\"," + "\"sync_window\":1000," +
               "\"tokentype\":\"hotp\"," + "\"user_editable\":false," + "\"user_id\":\"5\"," +
               "\"user_realm\":\"defrealm\"," + "\"username\":\"Test\"}]}}," + "\"time\":1648549489.57896," +
               "\"version\":\"privacyIDEA3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:58c4eed1...5247c47e3e\"}";
    }

    public static String getTokenNoTokenResponse()
    {
        return "{\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":{" +
               "\"count\":0," + "\"current\":1," + "\"tokens\":[]}}," + "\"time\":1648548984.9165428," +
               "\"version\":\"privacyIDEA3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:5295e005a48b0a915a1e37f80\"}";
    }

    public static String pollGetChallenges()
    {
        return "{\n" + "  \"detail\": {\n" +
               "    \"preferred_client_mode\": \"poll\",\n" +
               "    \"attributes\": null,\n" +
               "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
               "    \"messages\": [\n" +
               "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
               "      \"Please confirm the authentication on your mobile device!\"\n" +
               "    ],\n" + "    \"multi_challenge\": [\n" + "      {\n" +
               "        \"attributes\": null,\n" +
               "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
               "        \"serial\": \"OATH00020121\",\n" +
               "        \"transaction_id\": \"02659936574063359702\",\n" +
               "        \"type\": \"hotp\"\n" + "      },\n" + "      {\n" +
               "        \"attributes\": null,\n" +
               "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
               "        \"serial\": \"PIPU0001F75E\",\n" +
               "        \"image\": \"dataimage\",\n" +
               "        \"transaction_id\": \"02659936574063359702\",\n" +
               "        \"type\": \"push\"\n" + "      }\n" + "    ],\n" +
               "    \"serial\": \"PIPU0001F75E\",\n" +
               "    \"threadid\": 140040525666048,\n" +
               "    \"transaction_id\": \"02659936574063359702\",\n" +
               "    \"transaction_ids\": [\n" + "      \"02659936574063359702\",\n" +
               "      \"02659936574063359702\"\n" + "    ],\n" +
               "    \"type\": \"push\"\n" + "  },\n" + "  \"id\": 1,\n" +
               "  \"jsonrpc\": \"2.0\",\n" + "  \"result\": {\n" +
               "    \"status\": true,\n" + "    \"value\": false\n" + "  },\n" +
               "  \"time\": 1589360175.594304,\n" +
               "  \"version\": \"privacyIDEA 3.2.1\",\n" +
               "  \"versionnumber\": \"3.2.1\",\n" +
               "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" + "}";
    }

    public static String foundMatchingChallenge()
    {
        return "{\n" + "    \"detail\": {\n" +
               "        \"message\": \"Found matching challenge\",\n" +
               "        \"serial\": \"PIPU0001F75E\",\n" +
               "        \"threadid\": 140586038396672\n" + "    },\n" +
               "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
               "    \"result\": {\n" + "        \"status\": true,\n" +
               "        \"value\": true\n" + "    },\n" +
               "    \"time\": 1589446811.2747126,\n" +
               "    \"version\": \"privacyIDEA 3.2.1\",\n" +
               "    \"versionnumber\": \"3.2.1\",\n" +
               "    \"signature\": \"rsa_sha256_pss:\"\n" + "}";
    }

    public static String matchingOneToken()
    {
        return "{\n" + "  \"detail\": {\n" + "    \"message\": \"matching 1 tokens\",\n" + "    \"otplen\": 6,\n" +
               "    \"serial\": \"PISP0001C673\",\n" + "    \"threadid\": 140536383567616,\n" +
               "    \"type\": \"totp\"\n" + "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" +
               "  \"result\": {\n" + "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" +
               "  \"time\": 1589276995.4397042,\n" + "  \"version\": \"privacyIDEA 3.2.1\",\n" +
               "  \"versionnumber\": \"3.2.1\",\n" + "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"\n" + "}";
    }

    public static String rolloutSuccess()
    {
        return "{\n" + "    \"detail\": {\n" + "        \"googleurl\": {\n" +
               "            \"description\": \"URL for google Authenticator\",\n" +
               "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
               "            \"value\": \"otpauth://hotp/OATH0003A0AA?secret=4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH&counter=1&digits=6&issuer=privacyIDEA\"\n" +
               "        },\n" + "        \"oathurl\": {\n" +
               "            \"description\": \"URL for OATH token\",\n" +
               "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
               "            \"value\": \"oathtoken:///addToken?name=OATH0003A0AA&lockdown=true&key=e0d5d4909065b1ba925f2583c66fd305b9816b07\"\n" +
               "        },\n" + "        \"otpkey\": {\n" +
               "            \"description\": \"OTP seed\",\n" +
               "            \"img\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
               "            \"value\": \"seed://e0d5d4909065b1ba925f2583c66fd305b9816b07\",\n" +
               "            \"value_b32\": \"4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH\"\n" +
               "        },\n" + "        \"rollout_state\": \"\",\n" +
               "        \"serial\": \"OATH0003A0AA\",\n" +
               "        \"threadid\": 140470638720768\n" + "    },\n" +
               "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
               "    \"result\": {\n" + "        \"status\": true,\n" +
               "        \"value\": true\n" + "    },\n" +
               "    \"time\": 1592834605.532012,\n" +
               "    \"version\": \"privacyIDEA 3.3.3\",\n" +
               "    \"versionnumber\": \"3.3.3\",\n" +
               "    \"signature\": \"rsa_sha256_pss:\"\n" + "}";
    }

    public static String rolloutViaChallenge()
    {
        return "{\"detail\":{" + "\"attributes\":null," + "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
               "\"image\": \"data:image/png;base64,iVBdgfgsdfgRK5CYII=\",\n" +
               "\"messages\":[\"BittegebenSieeinenOTP-Wertein:\"]," + "\"multi_challenge\":[{" +
               "\"attributes\":null," + "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
               "\"serial\":\"TOTP00021198\"," + "\"transaction_id\":\"16734787285577957577\"," +
               "\"type\":\"totp\"}]," + "\"serial\":\"TOTP00021198\"," + "\"threadid\":140050885818112," +
               "\"transaction_id\":\"16734787285577957577\"," +
               "\"transaction_ids\":[\"16734787285577957577\"]," + "\"type\":\"totp\"}," + "\"id\":1," +
               "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," +
               "\"time\":1649666174.5351279," + "\"version\":\"privacyIDEA3.6.3\"," +
               "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b\"}";
    }

    public static String triggerChallengeSuccess()
    {
        return "{\"detail\":{" + "\"preferred_client_mode\":\"interactive\"," + "\"attributes\":null," +
               "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
               "\"messages\":[\"BittegebenSieeinenOTP-Wertein:\"]," + "\"multi_challenge\":[{" +
               "\"attributes\":null," + "\"message\":\"BittegebenSieeinenOTP-Wertein:\"," +
               "\"serial\":\"TOTP00021198\"," + "\"transaction_id\":\"16734787285577957577\"," +
               "\"image\":\"dataimage\"," + "\"type\":\"totp\"}]," + "\"serial\":\"TOTP00021198\"," +
               "\"threadid\":140050885818112," + "\"transaction_id\":\"16734787285577957577\"," +
               "\"transaction_ids\":[\"16734787285577957577\"]," + "\"type\":\"totp\"}," + "\"id\":1," +
               "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," +
               "\"time\":1649666174.5351279," + "\"version\":\"privacyIDEA3.6.3\"," +
               "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:4b0f0e12c2...89409a2e65c87d27b\"}";
    }

    public static String lostValues()
    {
        return "{\n" + "  \"detail\": {\n" + "    \"threadid\": 140536383567616,\n" + "  \"result\": {\n" +
               "    \"status\": true,\n" + "    \"value\": true\n" + "  },\n" + "  \"time\": 1589276995.4397042,\n" +
               "  \"version\": \"privacyIDEA None\",\n" + "}";
    }

    public static String errorUserNotFound()
    {
        return "{" + "\"detail\":null," + "\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"error\":{" +
               "\"code\":904," + "\"message\":\"ERR904: The user can not be found in any resolver in this realm!\"}," +
               "\"status\":false}," + "\"time\":1649752303.65651," + "\"version\":\"privacyIDEA 3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0\"}";
    }

    public static String webauthnSignRequest()
    {
        return "{\n" + "            \"allowCredentials\": [\n" + "              {\n" +
               "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
               "                \"transports\": [\n" + "                  \"internal\",\n" + "                  \"nfc\",\n" +
               "                  \"ble\",\n" + "                  \"usb\"\n" + "                ],\n" +
               "                \"type\": \"public-key\"\n" + "              }\n" + "            ],\n" +
               "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
               "            \"rpId\": \"office.netknights.it\",\n" + "            \"timeout\": 60000,\n" +
               "            \"userVerification\": \"preferred\"\n" + "          }\n";
    }

    public static String triggerWebauthn()
    {
        return "{\n" + "  \"detail\": {\n" + "    \"preferred_client_mode\": \"webauthn\",\n" + "    \"attributes\": {\n" +
               "      \"hideResponseInput\": true,\n" + "      \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
               "      \"webAuthnSignRequest\": {\n" + "        \"allowCredentials\": [\n" + "          {\n" +
               "            \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
               "            \"transports\": [\n" + "              \"internal\",\n" + "              \"nfc\",\n" +
               "              \"ble\",\n" + "              \"usb\"\n" + "            ],\n" + "            \"type\": \"public-key\"\n" +
               "          }\n" + "        ],\n" + "        \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
               "        \"rpId\": \"office.netknights.it\",\n" + "        \"timeout\": 60000,\n" +
               "        \"userVerification\": \"preferred\"\n" + "      }\n" + "    },\n" +
               "    \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
               "    \"messages\": [\n" + "      \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"\n" +
               "    ],\n" + "    \"multi_challenge\": [\n" + "      {\n" + "        \"attributes\": {\n" +
               "          \"hideResponseInput\": true,\n" + "          \"webAuthnSignRequest\": " + webauthnSignRequest() + "        },\n" +
               "          \"image\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
               "          \"client_mode\": \"webauthn\",\n" +
               "          \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
               "          \"serial\": \"WAN00025CE7\",\n" + "        \"transaction_id\": \"16786665691788289392\",\n" +
               "          \"type\": \"webauthn\"\n" + "      }\n" + "    ],\n" + "    \"serial\": \"WAN00025CE7\",\n" +
               "    \"threadid\": 140040275289856,\n" + "    \"transaction_id\": \"16786665691788289392\",\n" +
               "    \"transaction_ids\": [\n" + "      \"16786665691788289392\"\n" + "    ],\n" + "    \"type\": \"webauthn\"\n" +
               "  },\n" + "  \"id\": 1,\n" + "  \"jsonrpc\": \"2.0\",\n" + "  \"result\": {\n" +
               "    \"authentication\": \"CHALLENGE\",\n" + "    \"status\": true,\n" + "    \"value\": false\n" + "  },\n" +
               "  \"time\": 1611916339.8448942\n" + "}\n" + "";
    }

    public static String multipleWebauthnResponse()
    {
        return "{" + "\"detail\":{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" +
               "\"allowCredentials\":[{" + "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...KwYxgitd4uoowT43EGm_x3mNhT1i-w\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}}," +
               "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," +
               "\"messages\":[\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"]," +
               "\"multi_challenge\":[{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" +
               "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}}," + "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\"," +
               "\"serial\":\"WAN0003ABB5\"," + "\"transaction_id\":\"00699705595414705468\"," + "\"type\":\"webauthn\"}," + "{\"attributes\":{" +
               "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" + "\"allowCredentials\":[{" +
               "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...wYxgitd4uoowT43EGm_x3mNhT1i-w\"," + "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," +
               "\"type\":\"public-key\"}]," + "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
               "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}}," +
               "\"message\":\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," + "\"serial\":\"WAN00042278\"," +
               "\"transaction_id\":\"00699705595414705468\"," + "\"type\":\"webauthn\"}]," + "\"serial\":\"WAN00042278\"," +
               "\"threadid\":140050952959744," + "\"transaction_id\":\"00699705595414705468\"," +
               "\"transaction_ids\":[\"00699705595414705468\",\"00699705595414705468\"]," + "\"type\":\"webauthn\"}," + "\"id\":1," +
               "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," + "\"time\":1649754970.915023," +
               "\"version\":\"privacyIDEA 3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:74fac28b3163d4ac3f76...9237bb6c32c0d03de39\"}";
    }

    public static String expectedMergedResponse()
    {
        return "{" + "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}," + "{" +
               "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...wYxgitd4uoowT43EGm_x3mNhT1i-w\"," + "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," +
               "\"type\":\"public-key\"}]," + "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
               "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}";
    }

    public static String expectedMergedResponseIncomplete()
    {
        return "{" + "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}";
    }

    public static String mergedSignRequestEmpty()
    {
        return "{" + "\"detail\":{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{}," +
               "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," +
               "\"messages\":[\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"]," +
               "\"multi_challenge\":[{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" +
               "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}}," + "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\"," +
               "\"serial\":\"WAN0003ABB5\"," + "\"transaction_id\":\"00699705595414705468\"," + "\"type\":\"webauthn\"}," + "{\"attributes\":{" +
               "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" + "\"allowCredentials\":[{" +
               "\"id\":\"kJCeTZ-AtzwuuF-BkzBNO_0...wYxgitd4uoowT43EGm_x3mNhT1i-w\"," + "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," +
               "\"type\":\"public-key\"}]," + "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," +
               "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," + "\"userVerification\":\"preferred\"}}," +
               "\"message\":\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," + "\"serial\":\"WAN00042278\"," +
               "\"transaction_id\":\"00699705595414705468\"," + "\"type\":\"webauthn\"}]," + "\"serial\":\"WAN00042278\"," +
               "\"threadid\":140050952959744," + "\"transaction_id\":\"00699705595414705468\"," +
               "\"transaction_ids\":[\"00699705595414705468\",\"00699705595414705468\"]," + "\"type\":\"webauthn\"}," + "\"id\":1," +
               "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," + "\"time\":1649754970.915023," +
               "\"version\":\"privacyIDEA 3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:74fac28b3163d4ac3f76...9237bb6c32c0d03de39\"}";
    }

    public static String mergedSignRequestIncomplete()
    {
        return "{" + "\"detail\":{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" +
               "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}}," +
               "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB), Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"," +
               "\"messages\":[\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\",\"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\"]," +
               "\"multi_challenge\":[{" + "\"attributes\":{" + "\"hideResponseInput\":true," + "\"img\":\"\"," + "\"webAuthnSignRequest\":{" +
               "\"allowCredentials\":[{" + "\"id\":\"EF0bpUwV8YRCzZgZp335GmPbKGU9g1...k2kvqHIPVG3HyBPEEdhLwQFgL2j16K2wEkD2\"," +
               "\"transports\":[\"ble\",\"nfc\",\"usb\",\"internal\"]," + "\"type\":\"public-key\"}]," +
               "\"challenge\":\"9pxFSjhXo3MwRLCd0HiLaGcjVFLxjXGqlhX52xrIo-k\"," + "\"rpId\":\"office.netknights.it\"," + "\"timeout\":60000," +
               "\"userVerification\":\"preferred\"}}," + "\"message\":\"Please confirm with your WebAuthn token (FT BioPass FIDO2 USB)\"," +
               "\"serial\":\"WAN0003ABB5\"," + "\"transaction_id\":\"00699705595414705468\"," + "\"type\":\"webauthn\"}]," +
               "\"serial\":\"WAN00042278\"," + "\"threadid\":140050952959744," + "\"transaction_id\":\"00699705595414705468\"," +
               "\"transaction_ids\":[\"00699705595414705468\",\"00699705595414705468\"]," + "\"type\":\"webauthn\"}," + "\"id\":1," +
               "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"status\":true," + "\"value\":false}," + "\"time\":1649754970.915023," +
               "\"version\":\"privacyIDEA 3.6.3\"," + "\"versionnumber\":\"3.6.3\"," +
               "\"signature\":\"rsa_sha256_pss:74fac28b3163d4ac3f76...9237bb6c32c0d03de39\"}";
    }
}
