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

package org.eclipse.edc.connector.controlplane.transfer.process;

import org.eclipse.edc.connector.controlplane.transfer.spi.observe.TransferProcessObservable;
import org.eclipse.edc.connector.controlplane.transfer.spi.store.TransferProcessStore;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.ResourceManifest;
import org.eclipse.edc.connector.controlplane.transfer.spi.types.TransferProcess;
import org.eclipse.edc.spi.monitor.Monitor;

public class TransferProcessStateManager {

    private final TransferProcessStore store;
    private final Monitor monitor;
    private final TransferProcessObservable observable;

    public TransferProcessStateManager(TransferProcessStore store, Monitor monitor, TransferProcessObservable observable) {
        this.store = store;
        this.monitor = monitor;
        this.observable = observable;
    }

    public void transitionToTerminated(TransferProcess transferProcess, String message) {
        transferProcess.setErrorDetail(message);
        monitor.warning(message);
        transitionToTerminated(transferProcess);
    }

    public void transitionProvisioningRequested(TransferProcess transferProcess) {
        transferProcess.transitionProvisioningRequested();
        update(transferProcess);
    }

    public void transitionToProvisioning(TransferProcess transferProcess, ResourceManifest manifest) {
        transferProcess.transitionProvisioning(manifest);
        observable.invokeForEach(l -> l.preProvisioning(transferProcess));
        update(transferProcess);
    }

    public void transitionToRequesting(TransferProcess transferProcess) {
        transferProcess.transitionRequesting();
        update(transferProcess);
    }

    public void transitionToTerminating(TransferProcess process, String message, Throwable... errors) {
        monitor.warning(message, errors);
        process.transitionTerminating(message);
        update(process);
    }

    private void transitionToTerminated(TransferProcess process) {
        process.transitionTerminated();
        observable.invokeForEach(l -> l.preTerminated(process));
        update(process);
        observable.invokeForEach(l -> l.terminated(process));
    }

    private void update(TransferProcess entity) {
        store.save(entity);
        monitor.debug(() -> "[%s] %s %s is now in state %s"
                .formatted(this.getClass().getSimpleName(), entity.getClass().getSimpleName(),
                        entity.getId(), entity.stateAsString()));
    }
}
