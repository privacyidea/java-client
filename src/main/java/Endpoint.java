import javax.json.*;
import javax.json.stream.JsonGenerator;
import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;


class Endpoint {

    private ILoggerBridge log;
    private String authToken;
    private List<String> excludedEndpointPrints = Arrays.asList(Constants.ENDPOINT_AUTH, Constants.ENDPOINT_POLL_TRANSACTION); //Collections.emptyList(); //
    private boolean doSSLVerify = true;
    private String serverURL;
    private String serviceAccountName;
    private String serviceAccountPass;

    Endpoint(String serverURL, boolean doSSLVerify, ILoggerBridge logger, String serviceAccountName, String serviceAccountPass) {
        this.serverURL = serverURL;
        this.doSSLVerify = doSSLVerify;
        this.log = logger;
        this.serviceAccountName = serviceAccountName;
        this.serviceAccountPass = serviceAccountPass;
    }

    /**
     * Make a http(s) call to the specified path, the URL is taken from the config.
     * If SSL Verification is turned off in the config, the endpoints certificate will not be verified.
     *
     * @param path              Path to the API endpoint
     * @param params            All necessary parameters for request
     * @param authTokenRequired whether the authorization header should be set
     * @param method            "POST" or "GET"
     * @return String containing the whole response
     */
    String sendRequest(String path, Map<String, String> params, boolean authTokenRequired, String method) {
        log.log("Sending to endpoint=" + path + " with params=" + params.toString() + " and method=" + method);
        StringBuilder paramsSB = new StringBuilder();
        params.forEach((key, value) -> {
            try {
                if (key != null) {
                    paramsSB.append(key).append("=");
                }
                if (value != null) {
                    paramsSB.append(URLEncoder.encode(value, StandardCharsets.UTF_8.toString()));
                }
                paramsSB.append("&");
            } catch (Exception e) {
                log.log(e);
            }
        });
        paramsSB.deleteCharAt(paramsSB.length() - 1);

        //_log.info("Params: " + paramsSB);

        try {
            String sURL = serverURL + path;
            if (method.equals("GET")) {
                sURL += "?" + paramsSB.toString();
            }
            URL url = new URL(sURL);

            HttpURLConnection con;
            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (url.openConnection());
            } else {
                con = (HttpURLConnection) (url.openConnection());
            }

            if (!doSSLVerify && con instanceof HttpsURLConnection) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
            }

            con.setDoOutput(true);
            con.setRequestMethod(method);

            if (authToken == null && authTokenRequired) {
                getAuthorizationToken();
            }

            if (authToken != null && authTokenRequired) {
                con.setRequestProperty("Authorization", authToken);
            } else if (authTokenRequired) {
                throw new IllegalStateException("No authorization token found but is needed!");
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
                log.log(path + " RESPONSE: " + prettyPrintJson(response));
            }

            return response;
        } catch (Exception e) {
            log.error(e);
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

    private void getAuthorizationToken() {
        if (authToken != null) {
            //_log.info("Auth token already set.");
            return;
        }

        if (serviceAccountName == null || serviceAccountName.isEmpty() || serviceAccountPass == null || serviceAccountPass.isEmpty()) {
            log.error("Service account information not set, cannot retrieve auth token");
            return;
        }

        //_log.info("Getting auth token from PI");
        Map<String, String> params = new HashMap<>();
        params.put(Constants.PARAM_KEY_USERNAME, serviceAccountPass);
        params.put(Constants.PARAM_KEY_PASSWORD, serviceAccountPass);
        String response = sendRequest(Constants.ENDPOINT_AUTH, params, false, Constants.POST);
        JsonObject body = Json.createReader(new StringReader(response)).readObject();
        JsonObject result = body.getJsonObject(Constants.JSON_KEY_RESULT);
        JsonObject value = result.getJsonObject(Constants.JSON_KEY_VALUE);
        authToken = value.getString(Constants.JSON_KEY_TOKEN);
        if (authToken == null) {
            log.error("Failed to get authorization token.");
            log.error("Unable to read response from privacyIDEA.");
        }
    }

    public static String prettyPrintJson(String json) {
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
