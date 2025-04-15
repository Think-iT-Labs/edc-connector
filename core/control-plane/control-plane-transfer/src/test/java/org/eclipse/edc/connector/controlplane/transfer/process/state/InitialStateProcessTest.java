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

package org.eclipse.edc.connector.controlplane.transfer.process.state;

import org.eclipse.edc.connector.controlplane.asset.spi.index.DataAddressResolver;
import org.eclipse.edc.connector.controlplane.policy.spi.store.PolicyArchive;
import org.eclipse.edc.connector.controlplane.transfer.TestResourceDefinition;
import org.eclipse.edc.connector.controlplane.transfer.process.TransferProcessStateManager;
import org.eclipse.edc.connector.controlplane.transfer.spi.flow.DataFlowManager;
import org.eclipse.edc.connector.controlplane.transfer.spi.provision.ResourceManifestGenerator;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.DataFlowResponse;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.ProvisionedResourceSet;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.ResourceManifest;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcessStates;
import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.spi.response.StatusResult;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess.Type.CONSUMER;
import static org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess.Type.PROVIDER;
import static org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcessStates.INITIAL;
import static org.eclipse.edc.spi.response.ResponseStatus.FATAL_ERROR;
import static org.eclipse.edc.spi.types.domain.DataAddress.EDC_DATA_ADDRESS_SECRET;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InitialStateProcessTest {

    private final TransferProcessStateManager stateManager = mock();
    private final PolicyArchive policyArchive = mock();
    private final DataFlowManager dataFlowManager = mock();
    private final ResourceManifestGenerator manifestGenerator = mock();
    private final DataAddressResolver addressResolver = mock();
    private final Vault vault = mock();
    private final InitialStateProcess stateProcess = new InitialStateProcess(stateManager, policyArchive, dataFlowManager, manifestGenerator, addressResolver, vault);

    @Nested
    class Consumer {
        @Test
        void initial_consumer_shouldTransitionToProvisioning() {
            var transferProcess = createTransferProcess(INITIAL);
            when(dataFlowManager.provision(any(), any())).thenReturn(StatusResult.failure(FATAL_ERROR));
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());
            var resourceManifest = ResourceManifest.Builder.newInstance().definitions(List.of(new TestResourceDefinition())).build();
            when(manifestGenerator.generateConsumerResourceManifest(any(TransferProcess.class), any(Policy.class)))
                    .thenReturn(Result.success(resourceManifest));

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verify(stateManager).transitionToProvisioning(transferProcess, resourceManifest);
        }

        @Test
        void initial_consumer_manifestEvaluationFailed_shouldTransitionToTerminated() {
            var transferProcess = createTransferProcess(INITIAL);
            when(dataFlowManager.provision(any(), any())).thenReturn(StatusResult.failure(FATAL_ERROR));
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());
            when(manifestGenerator.generateConsumerResourceManifest(any(TransferProcess.class), any(Policy.class)))
                    .thenReturn(Result.failure("error"));

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verify(stateManager).transitionToTerminated(same(transferProcess), isA(String.class));
        }

        @Test
        void initial_consumer_shouldTransitionToTerminated_whenNoPolicyFound() {
            var transferProcess = createTransferProcess(INITIAL);
            when(dataFlowManager.provision(any(), any())).thenReturn(StatusResult.failure(FATAL_ERROR));
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(null);

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verify(stateManager).transitionToTerminated(same(transferProcess), isA(String.class));
        }

        @Test
        void shouldTransitionToProvisioningRequested_whenProvisionThroughDataplaneSucceeds() {
            var dataPlaneId = UUID.randomUUID().toString();
            var dataFlowResponse = DataFlowResponse.Builder.newInstance()
                    .dataPlaneId(dataPlaneId)
                    .provisioning(true)
                    .build();
            var transferProcess = createTransferProcess(INITIAL);
            when(dataFlowManager.provision(any(), any())).thenReturn(StatusResult.success(dataFlowResponse));
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verifyNoInteractions(manifestGenerator);
            var captor = ArgumentCaptor.forClass(TransferProcess.class);
            verify(stateManager).transitionProvisioningRequested(captor.capture());
            var storedTransferProcess = captor.getValue();
            assertThat(storedTransferProcess.getDataPlaneId()).isEqualTo(dataPlaneId);
        }

        @Test
        void shouldTransitionToRequesting_whenProvisionThroughDataplaneSucceedsButNoActualProvisionNeeded() {
            var dataPlaneId = UUID.randomUUID().toString();
            var dataFlowResponse = DataFlowResponse.Builder.newInstance()
                    .dataPlaneId(dataPlaneId)
                    .provisioning(false)
                    .build();
            var transferProcess = createTransferProcess(INITIAL);
            when(dataFlowManager.provision(any(), any())).thenReturn(StatusResult.success(dataFlowResponse));
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verifyNoInteractions(manifestGenerator);
            var captor = ArgumentCaptor.forClass(TransferProcess.class);
            verify(stateManager).transitionToRequesting(captor.capture());
            var storedTransferProcess = captor.getValue();
            assertThat(storedTransferProcess.getDataPlaneId()).isEqualTo(null);
        }
    }

    @Nested
    class Provider {

        private final TransferProcess.Builder builder = createTransferProcessBuilder(INITIAL).type(PROVIDER);

        @Test
        void shouldTransitionToProvisioning() {
            var transferProcess = builder.dataDestination(null).build();
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());
            var contentDataAddress = DataAddress.Builder.newInstance().type("type").build();
            when(addressResolver.resolveForAsset(any())).thenReturn(contentDataAddress);
            var resourceManifest = ResourceManifest.Builder.newInstance().definitions(List.of(new TestResourceDefinition())).build();
            when(manifestGenerator.generateProviderResourceManifest(any(TransferProcess.class), any(), any()))
                    .thenReturn(resourceManifest);

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            var captor = ArgumentCaptor.forClass(TransferProcess.class);
            verify(stateManager).transitionToProvisioning(captor.capture(), same(resourceManifest));
            verify(manifestGenerator).generateProviderResourceManifest(any(), any(), any());
            verifyNoInteractions(vault);
            var actualTransferProcess = captor.getValue();
            assertThat(actualTransferProcess.getContentDataAddress()).isSameAs(contentDataAddress);
        }

        @Test
        void shouldStoreSecret_whenItIsFoundInTheDataAddress() {
            var destinationDataAddress = DataAddress.Builder.newInstance()
                    .keyName("keyName")
                    .type("type")
                    .property(EDC_DATA_ADDRESS_SECRET, "secret")
                    .build();
            var transferProcess = builder.dataDestination(destinationDataAddress).build();
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());
            when(addressResolver.resolveForAsset(any())).thenReturn(DataAddress.Builder.newInstance().type("type").build());
            var resourceManifest = ResourceManifest.Builder.newInstance().definitions(List.of(new TestResourceDefinition())).build();
            when(manifestGenerator.generateProviderResourceManifest(any(TransferProcess.class), any(), any()))
                    .thenReturn(resourceManifest);

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(vault).storeSecret("keyName", "secret");
            verify(stateManager).transitionToProvisioning(transferProcess, resourceManifest);
        }

        @Test
        void shouldTransitionToTerminating_whenAssetIsNotResolved() {
            var transferProcess = builder.build();
            when(policyArchive.findPolicyForContract(anyString())).thenReturn(Policy.Builder.newInstance().build());
            when(addressResolver.resolveForAsset(any())).thenReturn(null);

            var processed = stateProcess.process(transferProcess);

            assertThat(processed).isTrue();
            verify(policyArchive, atLeastOnce()).findPolicyForContract(anyString());
            verify(stateManager).transitionToTerminating(same(transferProcess), anyString());
            verifyNoInteractions(manifestGenerator);
        }
    }

    private TransferProcess createTransferProcess(TransferProcessStates inState) {
        return createTransferProcessBuilder(inState).build();
    }

    private TransferProcess.Builder createTransferProcessBuilder(TransferProcessStates state) {
        var processId = UUID.randomUUID().toString();

        return TransferProcess.Builder.newInstance()
                .provisionedResourceSet(ProvisionedResourceSet.Builder.newInstance().build())
                .type(CONSUMER)
                .id("test-process-" + processId)
                .state(state.code())
                .correlationId(UUID.randomUUID().toString())
                .counterPartyAddress("http://an/address")
                .contractId(UUID.randomUUID().toString())
                .assetId(UUID.randomUUID().toString())
                .dataDestination(DataAddress.Builder.newInstance().type("any").build())
                .protocol("protocol");
    }

}
