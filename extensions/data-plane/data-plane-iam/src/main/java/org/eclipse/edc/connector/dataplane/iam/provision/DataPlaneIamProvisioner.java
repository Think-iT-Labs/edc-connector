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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessTokenService;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionedResource;
import org.eclipse.edc.connector.dataplane.spi.provision.Provisioner;
import org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.response.StatusResult;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.security.Vault;

import java.time.Clock;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_PARTICIPANT_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_RESPONSE_CHANNEL_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_PREFIX;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.SECRET_RESPONSE_CHANNEL_PREFIX;

/**
 * Issue token for EDR and store it in the vault
 * It works for both front and response channels.
 */
public class DataPlaneIamProvisioner implements Provisioner {

    private final String ownParticipantId;
    private final DataPlaneAccessTokenService accessTokenService;
    private final Vault vault;
    private final Clock clock;
    private final ObjectMapper mapper;
    private final String provisionType;
    private final String secretPrefix;

    public static DataPlaneIamProvisioner frontChannelProvisioner(String ownParticipantId, DataPlaneAccessTokenService accessTokenService,
                                                                  Vault vault, Clock clock, ObjectMapper mapper) {
        return new DataPlaneIamProvisioner(ownParticipantId, accessTokenService, vault, clock, mapper,
                PROVISION_TYPE, SECRET_PREFIX);
    }

    public static DataPlaneIamProvisioner responseChannelProvisioner(String ownParticipantId, DataPlaneAccessTokenService accessTokenService,
                                                                     Vault vault, Clock clock, ObjectMapper mapper) {
        return new DataPlaneIamProvisioner(ownParticipantId, accessTokenService, vault, clock, mapper,
                PROVISION_RESPONSE_CHANNEL_TYPE, SECRET_RESPONSE_CHANNEL_PREFIX);
    }

    private DataPlaneIamProvisioner(String ownParticipantId, DataPlaneAccessTokenService accessTokenService, Vault vault,
                                    Clock clock, ObjectMapper mapper, String provisionType, String secretPrefix) {
        this.ownParticipantId = ownParticipantId;
        this.accessTokenService = accessTokenService;
        this.vault = vault;
        this.clock = clock;
        this.mapper = mapper;
        this.provisionType = provisionType;
        this.secretPrefix = secretPrefix;
    }

    @Override
    public String supportedType() {
        return provisionType;
    }

    @Override
    public CompletableFuture<StatusResult<ProvisionedResource>> provision(ProvisionResource provisionResource) {
        var participantId = provisionResource.getProperty(PROPERTY_PARTICIPANT_ID).toString();
        var secretKey = secretPrefix + provisionResource.getFlowId();
        var tokenRepresentationResult = accessTokenService.obtainToken(createTokenParams(participantId), provisionResource.getDataAddress(), provisionResource.getProperties())
                .compose(this::serialize)
                .compose(tokenRepresentation -> vault.storeSecret(secretKey, tokenRepresentation)
                        .<ProvisionedResource, Result<ProvisionedResource>>map(v -> createProvisionedResource(provisionResource, secretKey)))
                .flatMap(DataPlaneIam::toStatusResult);

        return CompletableFuture.completedFuture(tokenRepresentationResult);
    }

    private Result<String> serialize(TokenRepresentation tokenRepresentation) {
        try {
            return Result.success(mapper.writeValueAsString(tokenRepresentation));
        } catch (JsonProcessingException e) {
            return Result.failure("Cannot serialize TokenRepresentation " + e.getMessage());
        }
    }

    private ProvisionedResource createProvisionedResource(ProvisionResource provisionResource, String secretKey) {
        return ProvisionedResource.Builder.from(provisionResource).secretKey(secretKey).pending(false).build();
    }

    private TokenParameters createTokenParams(String participantId) {
        return TokenParameters.Builder.newInstance()
                .claims(JwtRegisteredClaimNames.JWT_ID, UUID.randomUUID().toString())
                .claims(JwtRegisteredClaimNames.AUDIENCE, participantId)
                .claims(JwtRegisteredClaimNames.ISSUER, ownParticipantId)
                .claims(JwtRegisteredClaimNames.SUBJECT, ownParticipantId)
                .claims(JwtRegisteredClaimNames.ISSUED_AT, clock.instant().getEpochSecond())
                .build();
    }
}
