package org.privacyidea;

import java.util.ArrayList;
import java.util.List;

public class WebAuthn extends Challenge{

    private final List<String> attributes = new ArrayList<>();
    private final String webAuthn;

    public WebAuthn(String serial, String message, String transaction_id, String type,  String webAuthn) {
        super(serial, message, transaction_id, type);
        this.webAuthn = webAuthn;
    }

    public List<String> getAttributes() {
        return attributes;
    }


    public String getWebAuthn() {
        return webAuthn;
    }
}
