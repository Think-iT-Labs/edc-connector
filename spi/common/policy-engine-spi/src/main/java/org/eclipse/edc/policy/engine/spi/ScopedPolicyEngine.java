/*
 *  Copyright (c) 2021 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *
 */

package org.eclipse.edc.policy.engine.spi;

import org.eclipse.edc.policy.engine.spi.plan.PolicyEvaluationPlan;
import org.eclipse.edc.policy.model.Action;
import org.eclipse.edc.policy.model.AtomicConstraint;
import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.policy.model.Rule;
import org.eclipse.edc.runtime.metamodel.annotation.ExtensionPoint;
import org.eclipse.edc.spi.result.Result;

/**
 * Evaluates policies.
 * <p>
 * A policy scope is a visibility and semantic boundary for a {@link Rule}. A rule binding associates a rule type (see below) with a scope identified by a key, thereby
 * making a policy visible in a scope. Rule and constraint functions can be bound to one or more scopes, limiting the semantics they implement to the scope they are
 * registered with.
 * <p>
 * A rule type has two manifestations: (1) The type of {@link Action} specified by a rule; or (2) The left-hand operand of an {@link AtomicConstraint} contained in the rule.
 * <p>
 * Scopes are hierarchical and delimited by {@link #DELIMITER}. Functions bound to parent scopes will be inherited in child scopes.
 */
@ExtensionPoint
public interface ScopedPolicyEngine<C extends PolicyContext> {

    Result<Void> evaluate(Policy policy, C context);

    Result<Void> validate(Policy policy);

    Policy filter(Policy policy);

    <R extends Rule> void registerFunction(Class<R> type, String key, AtomicConstraintRuleFunction<R, C> function);

    <R extends Rule> void registerFunction(Class<R> type, DynamicAtomicConstraintRuleFunction<R, C> function);

    <R extends Rule> void registerFunction(Class<R> type, RulePolicyFunction<R, C> function);

    void registerPreValidator(PolicyValidatorFunction validator);

    void registerPostValidator(PolicyValidatorFunction validator);

    PolicyEvaluationPlan createEvaluationPlan(Policy policy);

}
