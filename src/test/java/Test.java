import org.junit.Before;

import java.util.Arrays;

public class Test implements ILoggerBridge, IPollTransactionCallback {

    private PrivacyIDEA privacyIDEA;
    private boolean waitForPushAuthSuccess = true;

    @Before
    public void setup() {
        privacyIDEA = new PrivacyIDEA.Builder("https://192.168.178.124", this)
                //.setPollingIntervals(Arrays.asList(5,5,1))
                .setSSLVerify(false)
                .setServiceAccount("admin", "admin")
                .build();
    }

    @org.junit.Test
    public void testValidateCheck() {
        PIResponse resp = privacyIDEA.validateCheck("mail", "057342");

        System.out.println("Success: " + resp.getValue());
    }

    @org.junit.Test
    public void testServiceTriggerPush() throws InterruptedException {
        PIResponse triggered = privacyIDEA.triggerChallenges("Administrator");

        System.out.println(triggered.getMessage());

        privacyIDEA.asyncPollTransaction(triggered.getTransactionID(), "Administrator", this);

        while (waitForPushAuthSuccess) {
            sleep(500);
        }
    }

    @org.junit.Test
    public void testTriggerPushNoService() {
        PrivacyIDEA privacyIDEA1 = new PrivacyIDEA.Builder("https://192.168.178.124", this)
                .setSSLVerify(false)
                .build();

        PIResponse response = privacyIDEA1.validateCheck("Administrator", "");

        privacyIDEA.asyncPollTransaction(response.getTransactionID(), "Administrator", this);

        while (waitForPushAuthSuccess) {
            sleep(500);
        }

    }

    @Override
    public void error(String message) {
        System.err.println(message);
    }

    @Override
    public void log(String message) {
        System.out.println(message);
    }

    @Override
    public void log(Throwable t) {
        System.out.println(t.getMessage());
    }

    @Override
    public void error(Throwable t) {
        System.err.println(t.getMessage());
    }

    @Override
    public void transactionFinalized(boolean success) {
        System.out.println("Transaction finalized with success: " + success);
        waitForPushAuthSuccess = false;
    }

    private void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
