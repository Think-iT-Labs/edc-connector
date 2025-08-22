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
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.eclipse.edc.spi.types.domain.transfer.FlowType;
import org.eclipse.edc.spi.types.domain.transfer.TransferType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_RESPONSE_CHANNEL_TYPE;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIam.PROVISION_TYPE;

class DataPlaneIamResourceGeneratorTest {

    @Test
    void shouldGenerateResource_frontChannel() {
        var resourceGenerator = DataPlaneIamResourceGenerator.frontChannelResourceGenerator();
        var sourceDataAddress = DataAddress.Builder.newInstance().type("source").build();
        var dataFlow = DataFlow.Builder.newInstance()
                .source(sourceDataAddress)
                .transferType(new TransferType("HttpData", FlowType.PULL))
                .build();

        assertThat(resourceGenerator.shouldGenerateFor(dataFlow)).isTrue();

        var provisionResource = resourceGenerator.generate(dataFlow);

        assertThat(provisionResource).isNotNull();
        assertThat(provisionResource.getFlowId()).isEqualTo(dataFlow.getId());
        assertThat(provisionResource.getType()).isEqualTo(PROVISION_TYPE);
        assertThat(provisionResource.getProperties()).hasSize(5);
        assertThat(provisionResource.getDataAddress()).isEqualTo(sourceDataAddress);
    }

    @Test
    void shouldGenerateResource_responseChannel() {
        var resourceGenerator = DataPlaneIamResourceGenerator.responseChannelResourceGenerator();
        var responseDataAddress = DataAddress.Builder.newInstance().type("response").build();
        var sourceDataAddress = DataAddress.Builder.newInstance().type("source").responseChannel(responseDataAddress).build();
        var dataFlow = DataFlow.Builder.newInstance()
                .source(sourceDataAddress)
                .transferType(new TransferType("HttpData", FlowType.PULL, "response"))
                .build();

        assertThat(resourceGenerator.shouldGenerateFor(dataFlow)).isTrue();

        var provisionResource = resourceGenerator.generate(dataFlow);

        assertThat(provisionResource).isNotNull();
        assertThat(provisionResource.getFlowId()).isEqualTo(dataFlow.getId());
        assertThat(provisionResource.getType()).isEqualTo(PROVISION_RESPONSE_CHANNEL_TYPE);
        assertThat(provisionResource.getProperties()).hasSize(5);
        assertThat(provisionResource.getDataAddress()).isEqualTo(responseDataAddress);
    }
}
