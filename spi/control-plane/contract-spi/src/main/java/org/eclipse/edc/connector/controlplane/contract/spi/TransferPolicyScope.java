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

import org.eclipse.edc.policy.engine.spi.PolicyScope;

public class TransferPolicyScope implements PolicyScope<TransferScopeContext> {
    @Override
    public String name() {
        return "transfer";
    }


}