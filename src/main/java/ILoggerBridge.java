public interface ILoggerBridge {
    void error(String message);

    void log(String message);

    void error(Throwable t);

    void log(Throwable t);
}
