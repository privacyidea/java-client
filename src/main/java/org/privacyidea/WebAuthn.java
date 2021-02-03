package org.privacyidea;

import java.util.ArrayList;
import java.util.List;

public class WebAuthn extends Challenge {

    private final List<String> attributes = new ArrayList<>();
    private final String signRequest;

    public WebAuthn(String serial, String message, String transaction_id, String signRequest) {
        super(serial, message, transaction_id, PIConstants.TOKEN_TYPE_WEBAUTHN);
        this.signRequest = signRequest;
    }

    public List<String> getAttributes() {
        return attributes;
    }


    public String getSignRequest() {
        return signRequest;
    }
}
