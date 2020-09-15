package org.privacyidea;

import java.util.ArrayList;
import java.util.List;

class Configuration {

    String serverURL = "";
    String realm = "";
    boolean doSSLVerify = true;
    String serviceAccountName = "";
    String serviceAccountPass = "";
    List<Integer> pollingIntervals = new ArrayList<>();
    boolean disableLog = false;

    public Configuration(String serverURL) {
        this.serverURL = serverURL;
    }
}
