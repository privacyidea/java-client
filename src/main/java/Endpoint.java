import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.json.JsonWriterFactory;
import javax.json.stream.JsonGenerator;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

class Endpoint {

    private final PrivacyIDEA privacyIDEA;
    private String authToken; // lazy init
    private List<String> excludedEndpointPrints = Collections.emptyList(); //Arrays.asList(Constants.ENDPOINT_AUTH, Constants.ENDPOINT_POLL_TRANSACTION);
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

        try {
            String strURL = hostname + path;

            if (method.equals("GET")) {
                strURL += "?" + paramsSB.toString();
            }
            URL url = new URL(strURL);
            HttpURLConnection con;

            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (url.openConnection());
            } else {
                con = (HttpURLConnection) (url.openConnection());
            }

            if (!doSSLVerify && (con instanceof HttpsURLConnection)) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
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

            String response;
            try (InputStream is = con.getInputStream()) {
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                response = br.lines().reduce("", (a, s) -> a += s);
            }

            if (!excludedEndpointPrints.contains(path)) {
                privacyIDEA.log(path + " RESPONSE: " + prettyPrintJson(response));
            }

            return response;
        } catch (Exception e) {
            privacyIDEA.log(e);
        }
        return null;
    }

    private HttpsURLConnection turnOffSSLVerification(HttpsURLConnection con) {
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

        if (serviceAccountName == null || serviceAccountName.isEmpty()
                || serviceAccountPass == null || serviceAccountPass.isEmpty()) {
            privacyIDEA.log("Service account information not set, cannot retrieve auth token");
            return;
        }

        //log.info("Getting auth token from PI");
        Map<String, String> params = new LinkedHashMap<>();
        params.put(Constants.PARAM_KEY_USERNAME, serviceAccountPass);
        params.put(Constants.PARAM_KEY_PASSWORD, serviceAccountPass);
        String response = sendRequest(Constants.ENDPOINT_AUTH, params, false, Constants.POST);

        JsonObject body = Json.createReader(new StringReader(response)).readObject();
        JsonObject result = body.getJsonObject(Constants.JSON_KEY_RESULT);
        JsonObject value = result.getJsonObject(Constants.JSON_KEY_VALUE);
        authToken = value.getString(Constants.JSON_KEY_TOKEN);
        if (authToken == null) {
            privacyIDEA.log("Failed to get authorization token.");
            privacyIDEA.log("Unable to read response from privacyIDEA.");
        }
    }

    String getAuthToken() {
        if (authToken == null) {
            getAuthTokenFromServer();
        }
        return authToken;
    }

    void setExcludedEndpointPrints(List<String> excludedEndpoints) {
        this.excludedEndpointPrints = excludedEndpoints;
    }

    public static String prettyPrintJson(String json) {
        if (json == null || json.isEmpty()) return "";

        StringWriter sw = new StringWriter();
        try {
            JsonReader jr = Json.createReader(new StringReader(json));
            JsonObject jobj = jr.readObject();

            Map<String, Object> properties = new HashMap<>(1);
            properties.put(JsonGenerator.PRETTY_PRINTING, true);

            JsonWriterFactory writerFactory = Json.createWriterFactory(properties);
            JsonWriter jsonWriter = writerFactory.createWriter(sw);

            jsonWriter.writeObject(jobj);
            jsonWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sw.toString();
    }
}
