package org.privacyidea;

import java.util.ArrayList;
import java.util.List;

public class WebAuthn extends Challenge{

    private final List<String> attributes = new ArrayList<>();
    private final String WebAuthn;

    public WebAuthn(String serial, String message, String transaction_id, String type, String WebAuthn) {
        super(serial, message, transaction_id, type);
        this.WebAuthn = WebAuthn;
    }

    public List<String> getAttributes() {
        return attributes;
    }


    public String getWebAuthn() {
        return WebAuthn;
    }
}
