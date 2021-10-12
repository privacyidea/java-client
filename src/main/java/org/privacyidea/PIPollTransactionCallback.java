package org.privacyidea;

/**
 * Copyright 2021 NetKnights GmbH - nils.behlen@netknights.it
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public interface PIPollTransactionCallback
{
    /**
     * If this method is invoked, the polling the status of the transaction_id passed to org.privacyidea.PrivacyIDEA::asyncPollTransaction
     * returned true.
     *
     * @param response the response of the finalizing call to /validate/check
     */
    void transactionFinalized(PIResponse response);
}
