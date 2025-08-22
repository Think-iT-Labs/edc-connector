/*
 *  Copyright (c) 2025 Think-it GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Think-it GmbH - initial API and implementation
 *
 */

package org.eclipse.edc.connector.dataplane.iam.provision;

import org.eclipse.edc.spi.response.ResponseStatus;
import org.eclipse.edc.spi.response.StatusResult;
import org.eclipse.edc.spi.result.AbstractResult;

/**
 * Constants for DataPlaneIam feature
 */
public interface DataPlaneIam {

    String PROVISION_TYPE = "HttpProxyToken";
    String PROVISION_RESPONSE_CHANNEL_TYPE = "HttpProxyTokenResponseChannel";
    String SECRET_PREFIX = "data-flow-proxy-token-";
    String SECRET_RESPONSE_CHANNEL_PREFIX = "data-flow-proxy-token-response-channel-";

    String PROPERTY_AGREEMENT_ID = "agreement_id";
    String PROPERTY_ASSET_ID = "asset_id";
    String PROPERTY_PROCESS_ID = "process_id";
    String PROPERTY_FLOW_TYPE = "flow_type";
    String PROPERTY_PARTICIPANT_ID = "participant_id";

    static <T> StatusResult<T> toStatusResult(AbstractResult<T, ?, ?> result) {
        if (result.succeeded()) {
            return StatusResult.success(result.getContent());
        } else {
            return StatusResult.failure(ResponseStatus.FATAL_ERROR, result.getFailureDetail());
        }
    }

}
