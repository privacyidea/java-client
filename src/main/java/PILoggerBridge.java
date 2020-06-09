interface PILoggerBridge {
    void log(String message);

    void error(String message);

    void log(Throwable t);

    void error(Throwable t);
}
