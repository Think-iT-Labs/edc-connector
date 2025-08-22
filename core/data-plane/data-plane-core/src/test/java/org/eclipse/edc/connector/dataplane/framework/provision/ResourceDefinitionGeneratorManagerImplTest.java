/*
 *  Copyright (c) 2025 Cofinity-X
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Cofinity-X - initial API and implementation
 *
 */

package org.eclipse.edc.connector.dataplane.framework.provision;

import org.eclipse.edc.connector.dataplane.spi.DataFlow;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionResource;
import org.eclipse.edc.connector.dataplane.spi.provision.ResourceDefinitionGenerator;
import org.eclipse.edc.connector.dataplane.spi.provision.ResourceDefinitionGeneratorManager;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceDefinitionGeneratorManagerImplTest {

    private final ResourceDefinitionGeneratorManager manager = new ResourceDefinitionGeneratorManagerImpl();

    @Nested
    class Consumer {

        @Test
        void generate_shouldGenerateResources() {
            var expectedProvisionResource = new ProvisionResource();
            manager.registerConsumerGenerator(generatorThatShouldGenerate(true, expectedProvisionResource));
            manager.registerConsumerGenerator(generatorThatShouldGenerate(false, new ProvisionResource()));
            var destination = DataAddress.Builder.newInstance().type("any").build();
            var dataFlow = DataFlow.Builder.newInstance().destination(destination).build();

            var definitions = manager.generateConsumerResourceDefinition(dataFlow);

            assertThat(definitions).hasSize(1).containsExactly(expectedProvisionResource);
        }

        @Test
        void destinationTypes_shouldReturnRegisteredDestinationTypes() {
            manager.registerConsumerGenerator(generatorWithSupportedType("supportedType"));
            manager.registerConsumerGenerator(generatorWithSupportedType(null));

            var types = manager.destinationTypes();

            assertThat(types).containsOnly("supportedType");
        }
    }

    @Nested
    class Provider {

        @Test
        void generate_shouldGenerateResources() {
            var expectedProvisionResource = new ProvisionResource();
            manager.registerProviderGenerator(generatorThatShouldGenerate(true, expectedProvisionResource));
            manager.registerProviderGenerator(generatorThatShouldGenerate(false, new ProvisionResource()));
            var source = DataAddress.Builder.newInstance().type("supportedType").build();
            var dataFlow = DataFlow.Builder.newInstance().source(source).build();

            var resources = manager.generateProviderResourceDefinition(dataFlow);

            assertThat(resources).hasSize(1).containsExactly(expectedProvisionResource);
        }

        @Test
        void sourceTypes_shouldReturnRegisteredSourceTypes() {
            manager.registerProviderGenerator(generatorWithSupportedType("supportedType"));
            manager.registerProviderGenerator(generatorWithSupportedType(null));

            var types = manager.sourceTypes();

            assertThat(types).containsOnly("supportedType");
        }

    }

    private ResourceDefinitionGenerator generatorThatShouldGenerate(boolean shouldGenerate, ProvisionResource provisionResource) {
        return new ResourceDefinitionGenerator() {
            @Override
            public String supportedType() {
                return "";
            }

            @Override
            public boolean shouldGenerateFor(DataFlow dataFlow) {
                return shouldGenerate;
            }

            @Override
            public ProvisionResource generate(DataFlow dataFlow) {
                return provisionResource;
            }
        };
    }

    private ResourceDefinitionGenerator generatorWithSupportedType(String sourceType) {
        return new ResourceDefinitionGenerator() {
            @Override
            public String supportedType() {
                return sourceType;
            }

            @Override
            public boolean shouldGenerateFor(DataFlow dataFlow) {
                return false;
            }

            @Override
            public ProvisionResource generate(DataFlow dataFlow) {
                return null;
            }
        };
    }
}
