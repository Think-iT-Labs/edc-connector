/*
 *  Copyright (c) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - initial API and implementation
 *
 */

package org.eclipse.edc.connector.dataplane.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.connector.dataplane.iam.service.DataPlaneAuthorizationServiceImpl;
import org.eclipse.edc.connector.dataplane.spi.AccessTokenData;
import org.eclipse.edc.connector.dataplane.spi.DataFlow;
import org.eclipse.edc.connector.dataplane.spi.Endpoint;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessControlService;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessTokenService;
import org.eclipse.edc.connector.dataplane.spi.iam.PublicEndpointGeneratorService;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionedResource;
import org.eclipse.edc.json.JacksonTypeManager;
import org.eclipse.edc.spi.iam.ClaimToken;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.eclipse.edc.spi.types.domain.transfer.FlowType;
import org.eclipse.edc.spi.types.domain.transfer.TransferType;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static jakarta.json.Json.createObjectBuilder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_PREFIX;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_RESPONSE_CHANNEL_PREFIX;
import static org.eclipse.edc.junit.assertions.AbstractResultAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class DataPlaneAuthorizationServiceImplTest {

    public static final String OWN_PARTICIPANT_ID = "test-ownParticipantId";
    private final DataPlaneAccessTokenService accessTokenService = mock();
    private final PublicEndpointGeneratorService endpointGenerator = mock();
    private final DataPlaneAccessControlService accessControlService = mock();
    private final Vault vault = mock();
    private final ObjectMapper mapper = new JacksonTypeManager().getMapper();
    private final DataPlaneAuthorizationServiceImpl authorizationService = new DataPlaneAuthorizationServiceImpl(
            accessTokenService, endpointGenerator, accessControlService, OWN_PARTICIPANT_ID, Clock.systemUTC(), vault, mapper);

    @Nested
    class CreateEndpointDataReference {

        @Test
        void shouldCreateEndpointDataReference() {
            when(endpointGenerator.generateFor(any(), any())).thenReturn(Result.success(Endpoint.url("http://example.com")));
            var secret = createObjectBuilder()
                    .add("token", "foo-token")
                    .add("additional", createObjectBuilder()
                            .add("authType", "bearer")
                            .add("fizz", "buzz")
                    ).build().toString();
            when(vault.resolveSecret(startsWith(SECRET_PREFIX))).thenReturn(secret);
            when(vault.resolveSecret(startsWith(SECRET_RESPONSE_CHANNEL_PREFIX))).thenReturn(null);
            var source = createDataAddress();
            var provisionResource = ProvisionResource.Builder.newInstance().flowId(UUID.randomUUID().toString()).build();
            provisionResource.transitionProvisioned(ProvisionedResource.Builder.from(provisionResource).secretKey("secretKey").build());
            var dataFlow = dataFlowBuilder()
                    .transferType(new TransferType("DestinationType", FlowType.PULL))
                    .participantId("participantId")
                    .source(source)
                    .resourceDefinitions(List.of(provisionResource))
                    .build();

            var result = authorizationService.createEndpointDataReference(dataFlow);
            assertThat(result).isSucceeded()
                    .satisfies(da -> {
                        assertThat(da.getType()).isEqualTo("https://w3id.org/idsa/v4.1/HTTP");
                        assertThat(da.getStringProperty("endpoint")).isEqualTo("http://example.com");
                        assertThat(da.getStringProperty("endpointType")).isEqualTo(da.getType());
                        assertThat(da.getStringProperty("authorization")).isEqualTo("foo-token");
                        assertThat(da.getStringProperty("authType")).isEqualTo("bearer");
                        assertThat(da.getStringProperty("fizz")).isEqualTo("buzz");
                    });
            verify(vault).resolveSecret(SECRET_PREFIX + dataFlow.getId());
            verify(endpointGenerator).generateFor("DestinationType", source);
        }

        @Test
        void shouldFail_whenTokenIsNotAvailableInVault() {
            when(vault.resolveSecret(any())).thenReturn(null);
            var dataFlow = dataFlowBuilder().build();

            var result = authorizationService.createEndpointDataReference(dataFlow);

            assertThat(result).isFailed().detail().contains("is not available");
        }

        @Test
        void shouldCreateResponseChannelEndpointDataReference() {
            when(vault.resolveSecret(startsWith(SECRET_PREFIX)))
                    .thenReturn(createObjectBuilder().add("token", "foo-token").build().toString());
            when(vault.resolveSecret(startsWith(SECRET_RESPONSE_CHANNEL_PREFIX)))
                    .thenReturn(createObjectBuilder().add("token", "foo-response-token").build().toString());
            when(endpointGenerator.generateFor(any(), any())).thenReturn(Result.success(Endpoint.url("http://example.com")));
            when(endpointGenerator.generateResponseFor(any())).thenReturn(Result.success(Endpoint.url("http://example.com/response")));
            var source = createDataAddressBuilder()
                    .responseChannel(createDataAddressBuilder().type("response-type").build())
                    .build();
            var provisionResource = ProvisionResource.Builder.newInstance().flowId(UUID.randomUUID().toString()).build();
            provisionResource.transitionProvisioned(ProvisionedResource.Builder.from(provisionResource).secretKey("secretKey").build());
            var dataFlow = dataFlowBuilder()
                    .transferType(new TransferType("DestinationType", FlowType.PULL))
                    .participantId("participantId")
                    .source(source)
                    .resourceDefinitions(List.of(provisionResource))
                    .build();

            var result = authorizationService.createEndpointDataReference(dataFlow);

            assertThat(result).isSucceeded()
                    .satisfies(da -> {
                        assertThat(da.getType()).isEqualTo("https://w3id.org/idsa/v4.1/HTTP");
                        assertThat(da.getStringProperty("endpoint")).isEqualTo("http://example.com");
                        assertThat(da.getStringProperty("endpointType")).isEqualTo(da.getType());
                        assertThat(da.getStringProperty("authorization")).isEqualTo("foo-token");
                        assertThat(da.getStringProperty("responseChannel-endpoint")).isEqualTo("http://example.com/response");
                        assertThat(da.getStringProperty("responseChannel-endpointType")).isEqualTo("https://w3id.org/idsa/v4.1/HTTP");
                        assertThat(da.getStringProperty("responseChannel-authorization")).isEqualTo("foo-response-token");
                    });
            verify(endpointGenerator).generateFor("DestinationType", source);
        }
    }

    @Test
    void authorize() {
        var claimToken = ClaimToken.Builder.newInstance().build();
        var address = DataAddress.Builder.newInstance().type("test-type").build();
        when(accessTokenService.resolve(eq("foo-token"))).thenReturn(Result.success(new AccessTokenData("test-id",
                claimToken,
                address)));
        when(accessControlService.checkAccess(eq(claimToken), eq(address), any(), anyMap())).thenReturn(Result.success());

        var result = authorizationService.authorize("foo-token", Map.of());

        assertThat(result).isSucceeded();
        verify(accessTokenService).resolve(eq("foo-token"));
        verify(accessControlService).checkAccess(eq(claimToken), eq(address), any(), anyMap());
        verifyNoMoreInteractions(accessTokenService, accessControlService);
    }

    @Test
    void authorize_tokenNotFound() {
        when(accessTokenService.resolve(eq("foo-token"))).thenReturn(Result.failure("not found"));

        var result = authorizationService.authorize("foo-token", Map.of());

        assertThat(result).isFailed().detail().isEqualTo("not found");
        verify(accessTokenService).resolve(eq("foo-token"));
        verifyNoMoreInteractions(accessTokenService, accessControlService);
    }

    @Test
    void authorize_accessNotGranted() {
        var claimToken = ClaimToken.Builder.newInstance().build();
        var address = DataAddress.Builder.newInstance().type("test-type").build();
        when(accessTokenService.resolve(eq("foo-token"))).thenReturn(Result.success(new AccessTokenData("test-id",
                claimToken,
                address)));
        when(accessControlService.checkAccess(eq(claimToken), eq(address), any(), anyMap())).thenReturn(Result.failure("not granted"));

        var result = authorizationService.authorize("foo-token", Map.of());

        assertThat(result).isFailed().detail().isEqualTo("not granted");
        verify(accessTokenService).resolve(eq("foo-token"));
        verify(accessControlService).checkAccess(eq(claimToken), eq(address), any(), anyMap());
        verifyNoMoreInteractions(accessTokenService, accessControlService);
    }

    @Test
    void revoke() {
        when(accessTokenService.revoke(eq("id"), eq("reason"))).thenReturn(ServiceResult.success());

        var result = authorizationService.revokeEndpointDataReference("id", "reason");

        assertThat(result).isSucceeded();
        verify(accessTokenService).revoke(eq("id"), eq("reason"));
        verifyNoMoreInteractions(accessTokenService, accessControlService);
    }

    @Test
    void revoke_error() {
        when(accessTokenService.revoke(eq("id"), eq("reason"))).thenReturn(ServiceResult.notFound("failure"));

        var result = authorizationService.revokeEndpointDataReference("id", "reason");

        assertThat(result).isFailed().detail().contains("failure");

        verify(accessTokenService).revoke(eq("id"), eq("reason"));
        verifyNoMoreInteractions(accessTokenService, accessControlService);
    }

    private DataAddress createDataAddress() {
        return createDataAddressBuilder().build();
    }

    private DataAddress.Builder createDataAddressBuilder() {
        return DataAddress.Builder.newInstance().type("test-src");
    }

    private DataFlow.Builder dataFlowBuilder() {
        return DataFlow.Builder.newInstance().transferType(new TransferType("any", FlowType.PULL));
    }
}
