import java.util.ArrayList;
import java.util.List;

public class Challenge {

    List<String> attributes = new ArrayList<String>();
    String serial;
    String message;
    String transaction_id;
    TokenType type;

    public Challenge(String serial, String message, String transaction_id, TokenType type) {
        this.serial = serial;
        this.message = message;
        this.transaction_id = transaction_id;
        this.type = type;
    }
}
