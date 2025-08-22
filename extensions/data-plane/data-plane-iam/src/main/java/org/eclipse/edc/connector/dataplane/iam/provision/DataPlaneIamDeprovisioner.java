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

import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessTokenService;
import org.eclipse.edc.connector.dataplane.spi.provision.DeprovisionedResource;
import org.eclipse.edc.connector.dataplane.spi.provision.Deprovisioner;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.spi.response.StatusResult;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;

import java.util.concurrent.CompletableFuture;

import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_RESPONSE_CHANNEL_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_TYPE;

/**
 * Revoke token and cleanup vault.
 * It works for both front and response channels.
 */
public class DataPlaneIamDeprovisioner implements Deprovisioner {

    private final DataPlaneAccessTokenService accessTokenService;
    private final Vault vault;
    private final String provisionType;

    public static DataPlaneIamDeprovisioner frontChannelDeprovisioner(DataPlaneAccessTokenService accessTokenService, Vault vault) {
        return new DataPlaneIamDeprovisioner(accessTokenService, vault, PROVISION_TYPE);
    }

    public static DataPlaneIamDeprovisioner responseChannelDeprovisioner(DataPlaneAccessTokenService accessTokenService, Vault vault) {
        return new DataPlaneIamDeprovisioner(accessTokenService, vault, PROVISION_RESPONSE_CHANNEL_TYPE);
    }

    private DataPlaneIamDeprovisioner(DataPlaneAccessTokenService accessTokenService, Vault vault, String provisionType) {
        this.accessTokenService = accessTokenService;
        this.vault = vault;
        this.provisionType = provisionType;
    }

    @Override
    public String supportedType() {
        return provisionType;
    }

    @Override
    public CompletableFuture<StatusResult<DeprovisionedResource>> deprovision(ProvisionResource provisionResource) {
        var secretKey = provisionResource.getProvisionedResource().getSecretKey();
        var deprovisioning = vault.deleteSecret(secretKey)
                .flatMap(ServiceResult::from)
                .compose(u -> accessTokenService.revoke(provisionResource.getFlowId(), null))
                .map(it -> DeprovisionedResource.Builder.from(provisionResource).pending(false).build())
                .flatMap(DataPlaneIam::toStatusResult);

        return CompletableFuture.completedFuture(deprovisioning);
    }
}
