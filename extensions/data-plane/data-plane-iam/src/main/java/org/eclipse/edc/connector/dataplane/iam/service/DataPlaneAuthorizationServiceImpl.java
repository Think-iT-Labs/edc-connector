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

package org.eclipse.edc.connector.dataplane.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam;
import org.eclipse.edc.connector.dataplane.spi.DataFlow;
import org.eclipse.edc.connector.dataplane.spi.Endpoint;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessControlService;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessTokenService;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAuthorizationService;
import org.eclipse.edc.connector.dataplane.spi.iam.PublicEndpointGeneratorService;
import org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.types.domain.DataAddress;

import java.time.Clock;
import java.util.Map;
import java.util.UUID;

import static org.eclipse.edc.spi.constants.CoreConstants.EDC_NAMESPACE;
import static org.eclipse.edc.spi.result.Result.success;

public class DataPlaneAuthorizationServiceImpl implements DataPlaneAuthorizationService {

    private final DataPlaneAccessTokenService accessTokenService;
    private final PublicEndpointGeneratorService endpointGenerator;
    private final DataPlaneAccessControlService accessControlService;
    private final String ownParticipantId;
    private final Clock clock;
    private final Vault vault;
    private final ObjectMapper mapper;

    public DataPlaneAuthorizationServiceImpl(DataPlaneAccessTokenService accessTokenService,
                                             PublicEndpointGeneratorService endpointGenerator,
                                             DataPlaneAccessControlService accessControlService,
                                             String ownParticipantId,
                                             Clock clock, Vault vault, ObjectMapper mapper) {
        this.accessTokenService = accessTokenService;
        this.endpointGenerator = endpointGenerator;
        this.accessControlService = accessControlService;
        this.ownParticipantId = ownParticipantId;
        this.clock = clock;
        this.vault = vault;
        this.mapper = mapper;
    }

    @Override
    public Result<DataAddress> createEndpointDataReference(DataFlow dataFlow) {
        var frontChannelSecretKey = DataPlaneIam.SECRET_PREFIX + dataFlow.getId();
        var frontChannelSecret = vault.resolveSecret(frontChannelSecretKey);
        if (frontChannelSecret == null) {
            return Result.failure("Cannot create EDR because the secret " + frontChannelSecretKey + " is not available");
        }

        var sourceDataAddress = dataFlow.getActualSource();

        var dataAddressBuilder = endpointGenerator.generateFor(dataFlow.getTransferType().destinationType(), sourceDataAddress)
                .compose(ep -> deserialize(frontChannelSecret)
                        .compose(token -> createDataAddress(token, ep)));

        var responseChannelSecretKey = DataPlaneIam.SECRET_RESPONSE_CHANNEL_PREFIX + dataFlow.getId();
        var responseChannelSecret = vault.resolveSecret(responseChannelSecretKey);
        if (responseChannelSecret != null) {
            var responseChannelType = dataFlow.getSource().getResponseChannel().getType();
            dataAddressBuilder = dataAddressBuilder.compose(builder -> endpointGenerator.generateResponseFor(responseChannelType)
                    .compose(endpoint -> deserialize(responseChannelSecret)
                            .compose(token -> addResponseChannel(builder, token, endpoint))));
        }

        return dataAddressBuilder.map(DataAddress.Builder::build);
    }

    @Override
    public Result<DataAddress> authorize(String token, Map<String, Object> requestData) {
        return accessTokenService.resolve(token)
                .compose(atd -> accessControlService.checkAccess(atd.claimToken(), atd.dataAddress(), requestData, atd.additionalProperties())
                        .map(u -> atd.dataAddress())
                );
    }

    @Override
    public ServiceResult<Void> revokeEndpointDataReference(String transferProcessId, String reason) {
        return accessTokenService.revoke(transferProcessId, reason);
    }

    private Result<TokenRepresentation> deserialize(String tokenRepresentationJson) {
        try {
            var tokenRepresentation = mapper.readValue(tokenRepresentationJson, TokenRepresentation.class);
            return Result.success(tokenRepresentation);
        } catch (JsonProcessingException e) {
            return Result.failure("Cannot deserialize TokenRepresentation: " + e.getMessage());
        }
    }

    private Result<DataAddress.Builder> createDataAddress(TokenRepresentation tokenRepresentation, Endpoint publicEndpoint) {
        var address = DataAddress.Builder.newInstance()
                .type(publicEndpoint.endpointType())
                .property(EDC_NAMESPACE + "endpoint", publicEndpoint.endpoint())
                .property(EDC_NAMESPACE + "endpointType", publicEndpoint.endpointType()) //this is duplicated in the type() field, but will make serialization easier
                .property(EDC_NAMESPACE + "authorization", tokenRepresentation.getToken())
                .properties(tokenRepresentation.getAdditional()); // would contain the "authType = bearer" entry

        return success(address);
    }

    private Result<DataAddress.Builder> addResponseChannel(DataAddress.Builder builder, TokenRepresentation tokenRepresentation, Endpoint returnChannelEndpoint) {
        builder
                .property(EDC_NAMESPACE + "responseChannel-endpoint", returnChannelEndpoint.endpoint())
                .property(EDC_NAMESPACE + "responseChannel-endpointType", returnChannelEndpoint.endpointType())
                .property(EDC_NAMESPACE + "responseChannel-authorization", tokenRepresentation.getToken());

        tokenRepresentation.getAdditional().forEach((k, v) -> builder.property(k.replace(EDC_NAMESPACE, EDC_NAMESPACE + "responseChannel-"), v.toString()));

        return Result.success(builder);

    }

    private TokenParameters createTokenParams(DataFlow dataFlow) {
        return TokenParameters.Builder.newInstance()
                .claims(JwtRegisteredClaimNames.JWT_ID, UUID.randomUUID().toString())
                .claims(JwtRegisteredClaimNames.AUDIENCE, dataFlow.getParticipantId())
                .claims(JwtRegisteredClaimNames.ISSUER, ownParticipantId)
                .claims(JwtRegisteredClaimNames.SUBJECT, ownParticipantId)
                .claims(JwtRegisteredClaimNames.ISSUED_AT, clock.instant().getEpochSecond())
                .build();
    }

    private record SecureEndpoint(Endpoint endpoint, TokenRepresentation tokenRepresentation) {
    }
}
