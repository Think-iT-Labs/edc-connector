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

import org.eclipse.edc.connector.dataplane.spi.DataFlow;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.connector.dataplane.spi.provision.ResourceDefinitionGenerator;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.eclipse.edc.spi.types.domain.transfer.FlowType;

import java.util.HashMap;
import java.util.function.Function;
import java.util.function.Predicate;

import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_AGREEMENT_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_ASSET_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_FLOW_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_PARTICIPANT_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROPERTY_PROCESS_ID;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_RESPONSE_CHANNEL_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_TYPE;

/**
 * Generate resource for provision for HttpData-PULL mechanism.
 * It can be used to generate either "front-channel" and "response-channel"
 */
public class DataPlaneIamResourceGenerator implements ResourceDefinitionGenerator {

    public static DataPlaneIamResourceGenerator frontChannelResourceGenerator() {
        return new DataPlaneIamResourceGenerator(
                PROVISION_TYPE,
                f -> true,
                DataFlow::getSource
        );
    }

    public static DataPlaneIamResourceGenerator responseChannelResourceGenerator() {
        return new DataPlaneIamResourceGenerator(
                PROVISION_RESPONSE_CHANNEL_TYPE,
                f -> f.getTransferType().responseChannelType() != null,
                f -> f.getSource().getResponseChannel()
        );
    }

    private final String provisionType;
    private final Predicate<DataFlow> additionalPredicate;
    private final Function<DataFlow, DataAddress> dataAddressSupplier;

    private DataPlaneIamResourceGenerator(String provisionType, Predicate<DataFlow> additionalPredicate, Function<DataFlow, DataAddress> dataAddressSupplier) {
        this.additionalPredicate = additionalPredicate;
        this.dataAddressSupplier = dataAddressSupplier;
        this.provisionType = provisionType;
    }

    @Override
    public String supportedType() {
        return null;
    }

    @Override
    public boolean shouldGenerateFor(DataFlow dataFlow) {
        var transferType = dataFlow.getTransferType();
        return FlowType.PULL == transferType.flowType() && "HttpData".equals(transferType.destinationType()) &&
                additionalPredicate.test(dataFlow);
    }

    @Override
    public ProvisionResource generate(DataFlow dataFlow) {
        var additionalProperties = new HashMap<String, Object>(dataFlow.getProperties());
        additionalProperties.put(PROPERTY_AGREEMENT_ID, dataFlow.getAgreementId());
        additionalProperties.put(PROPERTY_ASSET_ID, dataFlow.getAssetId());
        additionalProperties.put(PROPERTY_PROCESS_ID, dataFlow.getId());
        additionalProperties.put(PROPERTY_FLOW_TYPE, dataFlow.getTransferType().flowType().toString());
        additionalProperties.put(PROPERTY_PARTICIPANT_ID, dataFlow.getParticipantId());
        return ProvisionResource.Builder.newInstance()
                .type(provisionType)
                .flowId(dataFlow.getId())
                .properties(additionalProperties)
                .dataAddress(dataAddressSupplier.apply(dataFlow))
                .build();
    }
}
