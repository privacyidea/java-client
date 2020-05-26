import java.util.ArrayList;
import java.util.List;

class Configuration {

    String serverURL = "";
    String realm = "";
    boolean doSSLVerify = true;
    String serviceAccountName = "";
    String serviceAccountPass = "";
    List<Integer> pollingIntervals = new ArrayList<>();

    public Configuration(String serverURL) {
        this.serverURL = serverURL;
    }
}
