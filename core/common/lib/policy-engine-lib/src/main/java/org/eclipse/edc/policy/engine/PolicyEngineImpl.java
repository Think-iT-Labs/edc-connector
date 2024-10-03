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

package org.eclipse.edc.policy.engine;

import org.eclipse.edc.policy.engine.spi.AtomicConstraintFunction;
import org.eclipse.edc.policy.engine.spi.AtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.DynamicAtomicConstraintFunction;
import org.eclipse.edc.policy.engine.spi.DynamicAtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.PolicyContext;
import org.eclipse.edc.policy.engine.spi.PolicyEngine;
import org.eclipse.edc.policy.engine.spi.PolicyScope;
import org.eclipse.edc.policy.engine.spi.PolicyValidatorFunction;
import org.eclipse.edc.policy.engine.spi.RuleFunction;
import org.eclipse.edc.policy.engine.spi.ScopedPolicyEngine;
import org.eclipse.edc.policy.engine.spi.plan.PolicyEvaluationPlan;
import org.eclipse.edc.policy.engine.validation.RuleValidator;
import org.eclipse.edc.policy.model.Operator;
import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.policy.model.Rule;
import org.eclipse.edc.spi.result.Result;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Default implementation of the policy engine.
 */
public class PolicyEngineImpl implements PolicyEngine {

    public static final String ALL_SCOPES_DELIMITED = ALL_SCOPES + DELIMITER;

    private final Map<PolicyScope<?>, ScopedPolicyEngine<?>> scopedEngines = new HashMap<>();

    private final ScopeFilter scopeFilter;
    private final RuleValidator ruleValidator;

    public PolicyEngineImpl(ScopeFilter scopeFilter, RuleValidator ruleValidator) {
        this.scopeFilter = scopeFilter;
        this.ruleValidator = ruleValidator;
    }

    public static boolean scopeFilter(String entry, String scope) {
        return ALL_SCOPES_DELIMITED.equals(entry) || scope.startsWith(entry);
    }

    @Override
    public Policy filter(Policy policy, String scope) {
        return forScope(new PolicyScope<>(scope)).filter(policy);
    }

    @Override
    public Result<Void> evaluate(String scope, Policy policy, PolicyContext context) {
        return forScope(new PolicyScope<>(scope)).evaluate(policy, context);
    }

    @Override
    public <C extends PolicyContext, S extends PolicyScope<C>> ScopedPolicyEngine<C> forScope(S scope) {
        return (ScopedPolicyEngine<C>) scopedEngines.computeIfAbsent(scope, s -> new ScopedPolicyEngineImpl<>(s, scopeFilter, ruleValidator));
    }

    @Override
    public Result<Void> validate(Policy policy) {
        return scopedEngines.values().stream()
                .map(it -> it.validate(policy))
                .reduce(Result.success(), Result::merge);
    }

    @Override
    public PolicyEvaluationPlan createEvaluationPlan(String scope, Policy policy) {
        return forScope(new PolicyScope<>(scope)).createEvaluationPlan(policy);
    }

    @Override
    public <R extends Rule> void registerFunction(String scope, Class<R> type, String key, AtomicConstraintFunction<R> function) {
        forScope(new PolicyScope<>(scope)).registerFunction(type, key, new AtomicConstraintRuleFunction<R, PolicyContext>() {
            @Override
            public boolean evaluate(Operator operator, Object rightValue, R rule, PolicyContext context) {
                return function.evaluate(operator, rightValue, rule, context);
            }

            @Override
            public Result<Void> validate(Operator operator, Object rightValue, R rule) {
                return function.validate(operator, rightValue, rule);
            }
        });
    }

    @Override
    public <R extends Rule> void registerFunction(String scope, Class<R> type, DynamicAtomicConstraintFunction<R> function) {
        forScope(new PolicyScope<>(scope)).registerFunction(type, new DynamicAtomicConstraintRuleFunction<>() {
            @Override
            public boolean evaluate(Object leftValue, Operator operator, Object rightValue, R rule, PolicyContext context) {
                return function.evaluate(leftValue, operator, rightValue, rule, context);
            }

            @Override
            public Result<Void> validate(Object leftValue, Operator operator, Object rightValue, R rule) {
                return function.validate(leftValue, operator, rightValue, rule);
            }

            @Override
            public boolean canHandle(Object leftValue) {
                return function.canHandle(leftValue);
            }
        });
    }

    @Override
    public <R extends Rule> void registerFunction(String scope, Class<R> type, RuleFunction<R> function) {
        forScope(new PolicyScope<>(scope)).registerFunction(type, function::evaluate);
    }

    @Override
    public void registerPreValidator(String scope, BiFunction<Policy, PolicyContext, Boolean> validator) {
        registerPreValidator(scope, new PolicyValidatorFunctionWrapper(validator));
    }

    @Override
    public void registerPreValidator(String scope, PolicyValidatorFunction validator) {
        forScope(new PolicyScope<>(scope)).registerPreValidator(validator);
    }

    @Override
    public void registerPostValidator(String scope, BiFunction<Policy, PolicyContext, Boolean> validator) {
        registerPostValidator(scope, new PolicyValidatorFunctionWrapper(validator));
    }

    @Override
    public void registerPostValidator(String scope, PolicyValidatorFunction validator) {
        forScope(new PolicyScope<>(scope)).registerPostValidator(validator);
    }

    private record PolicyValidatorFunctionWrapper(
            BiFunction<Policy, PolicyContext, Boolean> function) implements PolicyValidatorFunction {

        @Override
        public Boolean apply(Policy policy, PolicyContext policyContext) {
            return function.apply(policy, policyContext);
        }

        @Override
        public String name() {
            return function.getClass().getSimpleName();
        }
    }

}
