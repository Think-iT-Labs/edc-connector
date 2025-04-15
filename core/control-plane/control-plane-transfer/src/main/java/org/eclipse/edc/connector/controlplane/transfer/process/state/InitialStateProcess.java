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
import org.eclipse.edc.connector.controlplane.transfer.process.TransferProcessStateManager;
import org.eclipse.edc.connector.controlplane.transfer.spi.flow.DataFlowManager;
import org.eclipse.edc.connector.controlplane.transfer.spi.provision.ResourceManifestGenerator;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.ResourceManifest;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.statemachine.StateProcess;

import static org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess.Type.CONSUMER;
import static org.eclipse.edc.spi.types.domain.DataAddress.EDC_DATA_ADDRESS_SECRET;

public class InitialStateProcess implements StateProcess<TransferProcess> {
    private final TransferProcessStateManager stateManager;
    private final PolicyArchive policyArchive;
    private final DataFlowManager dataFlowManager;
    private final ResourceManifestGenerator manifestGenerator;
    private final DataAddressResolver addressResolver;
    private final Vault vault;

    public InitialStateProcess(TransferProcessStateManager stateManager, PolicyArchive policyArchive, DataFlowManager dataFlowManager, ResourceManifestGenerator manifestGenerator, DataAddressResolver addressResolver, Vault vault) {
        this.stateManager = stateManager;
        this.policyArchive = policyArchive;
        this.dataFlowManager = dataFlowManager;
        this.manifestGenerator = manifestGenerator;
        this.addressResolver = addressResolver;
        this.vault = vault;
    }

    @Override
    public boolean process(TransferProcess transferProcess) {
        var contractId = transferProcess.getContractId();
        var policy = policyArchive.findPolicyForContract(contractId);

        if (policy == null) {
            stateManager.transitionToTerminated(transferProcess, "Policy not found for contract: " + contractId);
            return true;
        }

        ResourceManifest manifest;
        if (transferProcess.getType() == CONSUMER) {
            var provisioning = dataFlowManager.provision(transferProcess, policy);
            if (provisioning.succeeded()) {
                var response = provisioning.getContent();
                if (response.isProvisioning()) {
                    transferProcess.setDataPlaneId(response.getDataPlaneId());
                    stateManager.transitionProvisioningRequested(transferProcess);
                } else {
                    transferProcess.setDataPlaneId(null);
                    stateManager.transitionToRequesting(transferProcess);
                }

                return true;
            }

            var manifestResult = manifestGenerator.generateConsumerResourceManifest(transferProcess, policy);
            if (manifestResult.failed()) {
                stateManager.transitionToTerminated(transferProcess, "Resource manifest for process %s cannot be modified to fulfil policy. %s".formatted(transferProcess.getId(), manifestResult.getFailureDetail()));
                return true;
            }
            manifest = manifestResult.getContent();
        } else {
            var assetId = transferProcess.getAssetId();
            var dataAddress = addressResolver.resolveForAsset(assetId);
            if (dataAddress == null) {
                stateManager.transitionToTerminating(transferProcess, "Asset not found: " + assetId);
                return true;
            }
            // default the content address to the asset address; this may be overridden during provisioning
            transferProcess.setContentDataAddress(dataAddress);

            var dataDestination = transferProcess.getDataDestination();
            if (dataDestination != null) {
                var secret = dataDestination.getStringProperty(EDC_DATA_ADDRESS_SECRET);
                if (secret != null) {
                    vault.storeSecret(dataDestination.getKeyName(), secret);
                }
            }

            manifest = manifestGenerator.generateProviderResourceManifest(transferProcess, dataAddress, policy);
        }

        stateManager.transitionToProvisioning(transferProcess, manifest);
        return true;
    }

}
