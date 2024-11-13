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

class PIConfig
{
    private final String serverURL;
    private final String userAgent;
    private String realm = "";
    private boolean verifySSL = true;
    private String serviceAccountName = "";
    private String serviceAccountPass = "";
    private String serviceAccountRealm = "";
    private boolean disableLog = false;
    private final boolean forwardClientIP = false;
    private int httpTimeoutMs = 30000;

    public PIConfig(String serverURL, String userAgent)
    {
        this.serverURL = serverURL;
        this.userAgent = userAgent;
    }

    // SETTERS

    public void setRealm(String realm)
    {
        this.realm = realm;
    }

    public void setVerifySSL(boolean verifySSL)
    {
        this.verifySSL = verifySSL;
    }

    public void setServiceAccountName(String serviceAccountName)
    {
        this.serviceAccountName = serviceAccountName;
    }

    public void setServiceAccountPass(String serviceAccountPass)
    {
        this.serviceAccountPass = serviceAccountPass;
    }

    public void setServiceAccountRealm(String serviceAccountRealm)
    {
        this.serviceAccountRealm = serviceAccountRealm;
    }

    public void setDisableLog(boolean disableLog)
    {
        this.disableLog = disableLog;
    }

    public void setHttpTimeoutMs(int httpTimeoutMs)
    {
        this.httpTimeoutMs = httpTimeoutMs;
    }

    // GETTERS

    public String getServerURL()
    {
        return serverURL;
    }

    public String getUserAgent()
    {
        return userAgent;
    }

    public String getRealm()
    {
        return realm;
    }

    public boolean getVerifySSL()
    {
        return verifySSL;
    }

    public String getServiceAccountName()
    {
        return serviceAccountName;
    }

    public String getServiceAccountPass()
    {
        return serviceAccountPass;
    }

    public String getServiceAccountRealm()
    {
        return serviceAccountRealm;
    }

    public boolean getDisableLog()
    {
        return disableLog;
    }

    public boolean getForwardClientIP()
    {
        return forwardClientIP;
    }

    public int getHttpTimeoutMs()
    {
        return httpTimeoutMs;
    }
}