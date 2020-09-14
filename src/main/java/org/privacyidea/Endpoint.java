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
    private String authToken; // lazy init
    private List<String> logExcludedEndpointPrints = Collections.emptyList(); //Arrays.asList(org.privacyidea.Constants.ENDPOINT_AUTH, org.privacyidea.Constants.ENDPOINT_POLL_TRANSACTION);
    private boolean doSSLVerify = true;
    private final String hostname;
    private final String serviceAccountName;
    private final String serviceAccountPass;

    Endpoint(PrivacyIDEA privacyIDEA, String hostname, boolean doSSLVerify, String serviceAccountName, String serviceAccountPass) {
        this.hostname = hostname;
        this.doSSLVerify = doSSLVerify;
        this.serviceAccountName = serviceAccountName;
        this.serviceAccountPass = serviceAccountPass;
        this.privacyIDEA = privacyIDEA;
    }

    /**
     * Make a https call to the specified path, the URL is taken from the config.
     * If SSL Verification is turned off in the config, the endpoints certificate will not be verified.
     *
     * @param path              Path to the API endpoint
     * @param params            All necessary parameters for request
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
            String strURL = hostname + path;

            if (method.equals("GET")) {
                strURL += "?" + paramsSB.toString();
            }
            URL url = new URL(strURL);

            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (url.openConnection());
            } else {
                con = (HttpURLConnection) (url.openConnection());
            }

            if (!doSSLVerify && (con instanceof HttpsURLConnection)) {
                con = disableSSLVerification((HttpsURLConnection) con);
            }

            if (method.equals("POST")) {
                con.setDoOutput(true);
            }
            con.setRequestMethod(method);

            if (authToken == null && authTokenRequired) {
                getAuthTokenFromServer();
            }

            if (authToken != null && authTokenRequired) {
                con.setRequestProperty("Authorization", authToken);
            } else if (authTokenRequired) {
                throw new IllegalStateException("Authorization token could not be acquired, but it is needed!");
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
                    privacyIDEA.log("Reponse from error: " + response);
                }
            } catch (IOException ioe) {
                privacyIDEA.log("Exception while getting ErrorStream: " + e.getMessage());
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

    private void getAuthTokenFromServer() {
        if (authToken != null) {
            // The TTL of the AuthToken should be long enough for the usage (default is 60min)
            //log.info("Auth token already set.");
            return;
        }

        if (!privacyIDEA.checkServiceAccountAvailable()) {
            privacyIDEA.log("Service account information not set, cannot retrieve auth token");
            return;
        }

        //log.info("Getting auth token from PI");
        Map<String, String> params = new LinkedHashMap<>();
        params.put(Constants.PARAM_KEY_USERNAME, serviceAccountName);
        params.put(Constants.PARAM_KEY_PASSWORD, serviceAccountPass);
        String response = sendRequest(Constants.ENDPOINT_AUTH, params, false, Constants.POST);

        JsonObject obj = JsonParser.parseString(response).getAsJsonObject();
        if (obj != null) {
            authToken = obj.getAsJsonObject("result").getAsJsonObject("value").getAsJsonPrimitive("token").getAsString();
        }
    }

    String getAuthToken() {
        if (authToken == null) {
            getAuthTokenFromServer();
        }
        return authToken;
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

        //return sw.toString();
        return gson.toJson(obj);
    }

    public List<String> getLogExcludedEndpoints() {
        return logExcludedEndpointPrints;
    }

    public void setLogExcludedEndpoints(List<String> list) {
        logExcludedEndpointPrints = list;
    }
}
