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
import org.eclipse.edc.json.JacksonTypeManager;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Clock;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_PARTICIPANT_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_PREFIX;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_RESPONSE_CHANNEL_PREFIX;
import static org.eclipse.edc.junit.assertions.AbstractResultAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DataPlaneIamProvisionerTest {

    private final DataPlaneAccessTokenService accessTokenService = Mockito.mock();
    private final Vault vault = Mockito.mock();

    @Test
    void shouldProvisionToken_frontChannel() {
        var provisioner = DataPlaneIamProvisioner.frontChannelProvisioner("ownParticipantId", accessTokenService, vault, Clock.systemDefaultZone(), new JacksonTypeManager().getMapper());
        when(accessTokenService.obtainToken(any(), any(), any())).thenReturn(Result.success(TokenRepresentation.Builder.newInstance().token("token").build()));
        when(vault.storeSecret(any(), any())).thenReturn(Result.success());
        var dataAddress = DataAddress.Builder.newInstance().type("any").build();
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .dataAddress(dataAddress)
                .property(PROPERTY_PARTICIPANT_ID, "participantId")
                .build();

        var future = provisioner.provision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isSucceeded().satisfies(provisionedResource -> {
                assertThat(provisionedResource.getSecretKey()).isEqualTo(SECRET_PREFIX + "flowId");
                assertThat(provisionedResource.isPending()).isFalse();
            });
        });
        verify(accessTokenService).obtainToken(any(), same(dataAddress), same(provisionResource.getProperties()));
        verify(vault).storeSecret(startsWith(SECRET_PREFIX), contains("token"));
    }

    @Test
    void shouldProvisionToken_responseChannel() {
        var provisioner = DataPlaneIamProvisioner.responseChannelProvisioner("ownParticipantId", accessTokenService, vault, Clock.systemDefaultZone(), new JacksonTypeManager().getMapper());
        when(accessTokenService.obtainToken(any(), any(), any())).thenReturn(Result.success(TokenRepresentation.Builder.newInstance().token("token").build()));
        when(vault.storeSecret(any(), any())).thenReturn(Result.success());
        var dataAddress = DataAddress.Builder.newInstance().type("any").build();
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .dataAddress(dataAddress)
                .property(PROPERTY_PARTICIPANT_ID, "participantId")
                .build();

        var future = provisioner.provision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isSucceeded().satisfies(provisionedResource -> {
                assertThat(provisionedResource.getSecretKey()).isEqualTo(SECRET_RESPONSE_CHANNEL_PREFIX + "flowId");
                assertThat(provisionedResource.isPending()).isFalse();
            });
        });
        verify(accessTokenService).obtainToken(any(), same(dataAddress), same(provisionResource.getProperties()));
        verify(vault).storeSecret(startsWith(SECRET_RESPONSE_CHANNEL_PREFIX), contains("token"));
    }

    @Test
    void shouldFail_whenTokenIssuanceFails() {
        var provisioner = DataPlaneIamProvisioner.frontChannelProvisioner("ownParticipantId", accessTokenService, vault, Clock.systemDefaultZone(), new JacksonTypeManager().getMapper());
        when(accessTokenService.obtainToken(any(), any(), any())).thenReturn(Result.failure("error issuing token"));
        var dataAddress = DataAddress.Builder.newInstance().type("any").build();
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .dataAddress(dataAddress)
                .property(PROPERTY_PARTICIPANT_ID, "participantId")
                .build();

        var future = provisioner.provision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isFailed().detail().isEqualTo("error issuing token");
        });
        verifyNoInteractions(vault);
    }

    @Test
    void shouldFail_whenSecretStoringFails() {
        var provisioner = DataPlaneIamProvisioner.frontChannelProvisioner("ownParticipantId", accessTokenService, vault, Clock.systemDefaultZone(), new JacksonTypeManager().getMapper());
        when(accessTokenService.obtainToken(any(), any(), any())).thenReturn(Result.success(TokenRepresentation.Builder.newInstance().token("token").build()));
        when(vault.storeSecret(any(), any())).thenReturn(Result.failure("error storing secret"));
        var dataAddress = DataAddress.Builder.newInstance().type("any").build();
        var provisionResource = ProvisionResource.Builder.newInstance()
                .flowId("flowId")
                .dataAddress(dataAddress)
                .property(PROPERTY_PARTICIPANT_ID, "participantId")
                .build();

        var future = provisioner.provision(provisionResource);

        assertThat(future).succeedsWithin(1, SECONDS).satisfies(result -> {
            assertThat(result).isFailed().detail().isEqualTo("error storing secret");
        });
    }
}
