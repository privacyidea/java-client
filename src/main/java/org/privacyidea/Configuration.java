package org.privacyidea;

import java.util.ArrayList;
import java.util.List;

class Configuration {

    String serverURL = "";
    String realm = "";
    boolean doSSLVerify = true;
    String serviceAccountName = "";
    String serviceAccountPass = "";
    String serviceAccountRealm = "";
    List<Integer> pollingIntervals = new ArrayList<>();
    boolean disableLog = false;
    String userAgent = "";

    public Configuration(String serverURL, String userAgent) {
        this.serverURL = serverURL;
        this.userAgent = userAgent;
    }
}
