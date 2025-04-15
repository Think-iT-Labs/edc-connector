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

package org.eclipse.edc.statemachine;

import org.eclipse.edc.spi.entity.StatefulEntity;

import java.util.function.Function;

/**
 * Function that gets applied on a state machine iteration on a {@link StatefulEntity}.
 * If the entity gets actually processed, returns true, else it returns false.
 *
 * The result value affects the delay mechanism evaluated in the retry process.
 *
 * @param <E> the entity type.
 */
public interface StateProcess<E extends StatefulEntity<E>> extends Function<E, Boolean> {

    boolean process(E entity);

    @Override
    default Boolean apply(E entity) {
        return process(entity);
    }
}
