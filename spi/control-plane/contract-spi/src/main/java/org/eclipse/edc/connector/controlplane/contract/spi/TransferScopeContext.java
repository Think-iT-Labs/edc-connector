/*
 *  Copyright (c) 2024 Cofinity-X
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

package org.eclipse.edc.connector.controlplane.contract.spi;

import org.eclipse.edc.connector.controlplane.contract.spi.types.agreement.ContractAgreement;
import org.eclipse.edc.policy.engine.spi.PolicyContext;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.List;

// TODO: find a better place for this
public class TransferScopeContext implements PolicyContext {

    private final Instant now;
    private ContractAgreement contractAgreement;

    public TransferScopeContext(Instant now) {
        this.now = now;
    }

    @Override
    public void reportProblem(String problem) {

    }

    @Override
    public boolean hasProblems() {
        return false;
    }

    @Override
    public @NotNull List<String> getProblems() {
        return List.of();
    }

    @Override
    public <T> T getContextData(Class<T> type) {
        return null;
    }

    @Override
    public <T> void putContextData(Class<T> type, T data) {

    }

    public Instant getNow() {
        return now;
    }

    public ContractAgreement getContractAgreement() {
        return contractAgreement;
    }
}
