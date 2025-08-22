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
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionedResource;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;
import org.junit.jupiter.api.Test;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.junit.assertions.AbstractResultAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DataPlaneIamDeprovisionerTest {

    private final DataPlaneAccessTokenService accessTokenService = mock();
    private final Vault vault = mock();

    @Test
    void shouldRevokeTokenAndCleanUpVault() {
        var deprovisioner = DataPlaneIamDeprovisioner.frontChannelDeprovisioner(accessTokenService, vault);
        when(accessTokenService.revoke(any(), any())).thenReturn(ServiceResult.success());
        when(vault.deleteSecret(any())).thenReturn(Result.success());
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .build();
        var provisionedResource = ProvisionedResource.Builder.from(provisionResource).secretKey("secretKey").build();
        provisionResource.transitionProvisioned(provisionedResource);

        var future = deprovisioner.deprovision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isSucceeded().satisfies(deprovisionedResource -> {
                assertThat(deprovisionedResource.isPending()).isFalse();
            });
        });
        verify(accessTokenService).revoke("flowId", null);
        verify(vault).deleteSecret("secretKey");
    }

    @Test
    void shouldFail_whenVaultDeletionFails() {
        var deprovisioner = DataPlaneIamDeprovisioner.frontChannelDeprovisioner(accessTokenService, vault);
        when(vault.deleteSecret(any())).thenReturn(Result.failure("error deleting secret"));
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .build();
        var provisionedResource = ProvisionedResource.Builder.from(provisionResource).secretKey("secretKey").build();
        provisionResource.transitionProvisioned(provisionedResource);

        var future = deprovisioner.deprovision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isFailed().detail().isEqualTo("error deleting secret");
        });
        verifyNoInteractions(accessTokenService);
    }

    @Test
    void shouldFail_whenRevocationFails() {
        var deprovisioner = DataPlaneIamDeprovisioner.frontChannelDeprovisioner(accessTokenService, vault);
        when(accessTokenService.revoke(any(), any())).thenReturn(ServiceResult.unexpected("error revoking token"));
        when(vault.deleteSecret(any())).thenReturn(Result.success());
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .build();
        var provisionedResource = ProvisionedResource.Builder.from(provisionResource).secretKey("secretKey").build();
        provisionResource.transitionProvisioned(provisionedResource);

        var future = deprovisioner.deprovision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isFailed().detail().isEqualTo("error revoking token");
        });
    }
}
