import java.util.ArrayList;
import java.util.List;

public class Challenge {

    private final List<String> attributes = new ArrayList<>();
    private final String serial;
    private final String message;
    private final String transaction_id;
    private final String type;

    public Challenge(String serial, String message, String transaction_id, String type) {
        this.serial = serial;
        this.message = message;
        this.transaction_id = transaction_id;
        this.type = type;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    public String getSerial() {
        return serial;
    }

    public String getMessage() {
        return message;
    }

    public String getTransactionID() {
        return transaction_id;
    }

    public String getType() {
        return type;
    }
}
