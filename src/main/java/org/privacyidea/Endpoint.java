package org.privacyidea;

import com.google.gson.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class Endpoint {

    private final PrivacyIDEA privacyIDEA;
    private List<String> logExcludedEndpointPrints = Collections.emptyList(); //Arrays.asList(org.privacyidea.Constants.ENDPOINT_AUTH, org.privacyidea.Constants.ENDPOINT_POLL_TRANSACTION);
    private final Configuration configuration;

    Endpoint(PrivacyIDEA privacyIDEA, Configuration configuration) {
        this.privacyIDEA = privacyIDEA;
        this.configuration = configuration;
    }

    /**
     * Make a https call to the specified path, the URL is taken from the config.
     * If SSL verification is set to false in the config, the endpoints certificate will not be verified.
     *
     * @param path              path to the API endpoint
     * @param params            all necessary parameters for the request
     * @param authTokenRequired whether the authorization header should be set
     * @param method            "POST" or "GET"
     * @return String containing the whole response
     */
    String sendRequest(String path, Map<String, String> params, boolean authTokenRequired, String method) {
        //log.log("Sending to endpoint=" + path + " with params=" + params.toString() + " and method=" + method);
        StringBuilder paramsSB = new StringBuilder();
        params.forEach((key, value) -> {
            if (key != null) {
                paramsSB.append(key).append("=");
            }
            if (value != null) {
                try {
                    paramsSB.append(URLEncoder.encode(value, StandardCharsets.UTF_8.toString()));
                } catch (Exception e) {
                    privacyIDEA.log(e);
                }
            }
            paramsSB.append("&");
        });
        // Delete trailing '&'
        if (paramsSB.length() > 1 && paramsSB.charAt(paramsSB.length() - 1) == '&') {
            paramsSB.deleteCharAt(paramsSB.length() - 1);
        }

        HttpURLConnection con = null;
        String response = null;
        try {
            String strURL = configuration.serverURL + path;

            if (method.equals("GET")) {
                strURL += "?" + paramsSB.toString();
            }
            URL url = new URL(strURL);

            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (url.openConnection());
            } else {
                con = (HttpURLConnection) (url.openConnection());
            }

            if (!configuration.doSSLVerify && (con instanceof HttpsURLConnection)) {
                con = disableSSLVerification((HttpsURLConnection) con);
            }

            if (method.equals("POST")) {
                con.setDoOutput(true);
            }

            con.setRequestMethod(method);
            con.addRequestProperty("User-Agent", configuration.userAgent);

            if (authTokenRequired) {
                String authToken = getAuthTokenFromServer();
                if (authToken.isEmpty()) {
                    privacyIDEA.log("Failed to fetch authorization token from server!");
                    return "";
                }

                con.setRequestProperty("Authorization", authToken);
            }

            con.connect();

            if (method.equals("POST")) {
                byte[] outputBytes = (paramsSB.toString()).getBytes(StandardCharsets.UTF_8);
                OutputStream os = con.getOutputStream();
                os.write(outputBytes);
                os.close();
            }

            try (InputStream is = con.getInputStream()) {
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                response = br.lines().reduce("", (a, s) -> a += s);
            }

            if (!logExcludedEndpointPrints.contains(path)) {
                privacyIDEA.log(path + ":");
                privacyIDEA.log(prettyPrintJson(response));
            }

            return response;
        } catch (Exception e) {
            privacyIDEA.log("Endpoint exception: " + e.getMessage());
            // If the server returns a different response code than 200, an exception is thrown
            // Try to read the response from the ErrorStream
            try {
                if (con != null && con.getResponseCode() != 200 && (response == null || response.isEmpty())) {
                    privacyIDEA.log("HttpResponseCode: " + con.getResponseCode() + ", reading response from ErrorStream...");
                    try (InputStream es = con.getErrorStream()) {
                        if (es != null) {
                            BufferedReader br = new BufferedReader(new InputStreamReader(es));
                            response = br.lines().reduce("", (a, s) -> a += s);
                        }
                    }
                    privacyIDEA.log("Response from ErrorStream: " + response);
                }
            } catch (IOException ioe) {
                privacyIDEA.log("Exception getting ErrorStream: " + ioe.getMessage());
            }

        }
        return response;
    }

    private HttpsURLConnection disableSSLVerification(HttpsURLConnection con) {
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
        };
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }

        if (sslContext == null) {
            return con;
        }

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        con.setSSLSocketFactory(sslSocketFactory);
        con.setHostnameVerifier((hostname, session) -> true);

        return con;
    }

    String getAuthTokenFromServer() {
        if (!privacyIDEA.checkServiceAccountAvailable()) {
            privacyIDEA.log("Service account information not set, cannot retrieve auth token");
            return "";
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put(Constants.PARAM_KEY_USERNAME, configuration.serviceAccountName);
        params.put(Constants.PARAM_KEY_PASSWORD, configuration.serviceAccountPass);

        if (configuration.serviceAccountRealm != null && !configuration.serviceAccountRealm.isEmpty()) {
            params.put(Constants.PARAM_KEY_REALM, configuration.serviceAccountRealm);
        } else if (configuration.realm != null && !configuration.realm.isEmpty()) {
            params.put(Constants.PARAM_KEY_REALM, configuration.realm);
        }

        String response = sendRequest(Constants.ENDPOINT_AUTH, params, false, Constants.POST);

        JsonObject obj = JsonParser.parseString(response).getAsJsonObject();
        if (obj != null) {
            return obj.getAsJsonObject("result").getAsJsonObject("value").getAsJsonPrimitive("token").getAsString();
        } else {
            privacyIDEA.log("Response did not contain an authorization token: " + response);
            return "";
        }
    }

    public static String prettyPrintJson(String json) {
        if (json == null || json.isEmpty()) return "";

        JsonObject obj;
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return json;
        }

        return gson.toJson(obj);
    }

    public List<String> getLogExcludedEndpoints() {
        return logExcludedEndpointPrints;
    }

    public void setLogExcludedEndpoints(List<String> list) {
        logExcludedEndpointPrints = list;
    }
}
