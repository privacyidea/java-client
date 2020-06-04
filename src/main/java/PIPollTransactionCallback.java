public interface PIPollTransactionCallback {

    /**
     * If this method is invoked, the polling the status of the transaction_id passed to PrivacyIDEA::asyncPollTransaction
     * returned true.
     *
     * @param response the response to the finalizing call to /validate/check
     */
    void transactionFinalized(PIResponse response);
}
