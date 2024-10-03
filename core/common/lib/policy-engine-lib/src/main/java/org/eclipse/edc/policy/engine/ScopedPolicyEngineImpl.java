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

package org.eclipse.edc.policy.engine;

import org.eclipse.edc.policy.engine.plan.PolicyEvaluationPlanner;
import org.eclipse.edc.policy.engine.spi.AtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.DynamicAtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.PolicyContext;
import org.eclipse.edc.policy.engine.spi.PolicyScope;
import org.eclipse.edc.policy.engine.spi.PolicyValidatorFunction;
import org.eclipse.edc.policy.engine.spi.RulePolicyFunction;
import org.eclipse.edc.policy.engine.spi.ScopedPolicyEngine;
import org.eclipse.edc.policy.engine.spi.plan.PolicyEvaluationPlan;
import org.eclipse.edc.policy.engine.validation.PolicyValidator;
import org.eclipse.edc.policy.engine.validation.RuleValidator;
import org.eclipse.edc.policy.evaluator.PolicyEvaluator;
import org.eclipse.edc.policy.evaluator.RuleProblem;
import org.eclipse.edc.policy.model.Duty;
import org.eclipse.edc.policy.model.Permission;
import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.policy.model.Prohibition;
import org.eclipse.edc.policy.model.Rule;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.eclipse.edc.policy.engine.PolicyEngineImpl.scopeFilter;
import static org.eclipse.edc.spi.result.Result.failure;

public class ScopedPolicyEngineImpl<S extends PolicyScope<C>, C extends PolicyContext> implements ScopedPolicyEngine<C> {

    private final PolicyScope<C> scope;
    private final ScopeFilter scopeFilter;
    private final RuleValidator ruleValidator;
    private final List<ConstraintFunction<Rule, C>> constraintFunctions = new ArrayList<>();
    private final List<DynamicConstraintFunction<Rule, C>> dynamicConstraintFunctions = new ArrayList<>();
    private final List<RuleFunction<Rule, C>> ruleFunctions = new ArrayList<>();
    private final List<PolicyValidatorFunction> preValidators = new ArrayList<>();
    private final List<PolicyValidatorFunction> postValidators = new ArrayList<>();

    public ScopedPolicyEngineImpl(PolicyScope<C> scope, ScopeFilter scopeFilter, RuleValidator ruleValidator) {
        this.scope = scope;
        this.scopeFilter = scopeFilter;
        this.ruleValidator = ruleValidator;
    }

    @Override
    public Result<Void> evaluate(Policy policy, C context) {
        var delimitedScope = scope.name() + ".";

        var preValidationFailure = preValidators.stream()
                .filter(entry -> scopeFilter(scope.name(), delimitedScope))
                .filter(v -> !v.apply(policy, context))
                .findAny();

        if (preValidationFailure.isPresent()) {
            return failValidator("Pre-validator", preValidationFailure.get(), context);
        }

        var evalBuilder = PolicyEvaluator.Builder.newInstance();

        ruleFunctions.stream().filter(entry -> scopeFilter(scope.name(), delimitedScope)).forEach(entry -> {
            if (Duty.class.isAssignableFrom(entry.type)) {
                evalBuilder.dutyRuleFunction((rule) -> entry.function.evaluate(rule, context));
            } else if (Permission.class.isAssignableFrom(entry.type)) {
                evalBuilder.permissionRuleFunction((rule) -> entry.function.evaluate(rule, context));
            } else if (Prohibition.class.isAssignableFrom(entry.type)) {
                evalBuilder.prohibitionRuleFunction((rule) -> entry.function.evaluate(rule, context));
            }
        });

        constraintFunctions.stream().filter(entry -> scopeFilter(scope.name(), delimitedScope)).forEach(entry -> {
            if (Duty.class.isAssignableFrom(entry.type)) {
                evalBuilder.dutyFunction(entry.key, (operator, value, duty) -> entry.function.evaluate(operator, value, duty, context));
            } else if (Permission.class.isAssignableFrom(entry.type)) {
                evalBuilder.permissionFunction(entry.key, (operator, value, permission) -> entry.function.evaluate(operator, value, permission, context));
            } else if (Prohibition.class.isAssignableFrom(entry.type)) {
                evalBuilder.prohibitionFunction(entry.key, (operator, value, prohibition) -> entry.function.evaluate(operator, value, prohibition, context));
            }
        });

        dynamicConstraintFunctions.stream().filter(entry -> scopeFilter(scope.name(), delimitedScope)).forEach(entry -> {
            if (Duty.class.isAssignableFrom(entry.type)) {
                evalBuilder.dynamicDutyFunction(entry.function::canHandle, (key, operator, value, duty) -> entry.function.evaluate(key, operator, value, duty, context));
            } else if (Permission.class.isAssignableFrom(entry.type)) {
                evalBuilder.dynamicPermissionFunction(entry.function::canHandle, (key, operator, value, permission) -> entry.function.evaluate(key, operator, value, permission, context));
            } else if (Prohibition.class.isAssignableFrom(entry.type)) {
                evalBuilder.dynamicProhibitionFunction(entry.function::canHandle, (key, operator, value, prohibition) -> entry.function.evaluate(key, operator, value, prohibition, context));
            }
        });

        var evaluator = evalBuilder.build();

        var filteredPolicy = scopeFilter.applyScope(policy, scope.name());

        var result = evaluator.evaluate(filteredPolicy);

        if (result.valid()) {

            var postValidationFailure = postValidators.stream()
                    .filter(entry -> scopeFilter(scope.name(), delimitedScope))
                    .filter(v -> !v.apply(policy, context))
                    .findAny();

            if (postValidationFailure.isPresent()) {
                return failValidator("Post-validator", postValidationFailure.get(), context);
            }

            return Result.success();
        } else {
            return Result.failure(result.getProblems().stream().map(RuleProblem::getDescription).toList());
        }
    }

    @Override
    public Result<Void> validate(Policy policy) {
        var validatorBuilder = PolicyValidator.Builder.newInstance()
                .ruleValidator(ruleValidator);

        constraintFunctions.forEach(entry -> validatorBuilder.evaluationFunction(entry.key, entry.type, entry.function));
        dynamicConstraintFunctions.forEach(entry -> validatorBuilder.dynamicEvaluationFunction(entry.type, entry.function));

        return validatorBuilder.build().validate(policy);
    }

    @Override
    public Policy filter(Policy policy) {
        return scopeFilter.applyScope(policy, scope.name());
    }

    @Override
    public <R extends Rule> void registerFunction(Class<R> type, String key, AtomicConstraintRuleFunction<R, C> function) {
        constraintFunctions.add(new ConstraintFunction(type, key, function));
    }

    @Override
    public <R extends Rule> void registerFunction(Class<R> type, DynamicAtomicConstraintRuleFunction<R, C> function) {
        dynamicConstraintFunctions.add(new DynamicConstraintFunction(type, function));
    }

    @Override
    public <R extends Rule> void registerFunction(Class<R> type, RulePolicyFunction<R, C> function) {
        ruleFunctions.add(new RuleFunction(type, function));
    }

    @Override
    public void registerPreValidator(PolicyValidatorFunction validator) {
        preValidators.add(validator);
    }

    @Override
    public void registerPostValidator(PolicyValidatorFunction validator) {
        postValidators.add(validator);
    }

    @Override
    public PolicyEvaluationPlan createEvaluationPlan(Policy policy) {
        var planner = PolicyEvaluationPlanner.Builder.newInstance(scope.name()).ruleValidator(ruleValidator);

        preValidators.forEach(planner::preValidator);
        postValidators.forEach(planner::postValidator);

        constraintFunctions.forEach(entry -> planner.evaluationFunction(entry.key, entry.type, entry.function));
        dynamicConstraintFunctions.forEach(dynFunctions -> planner.evaluationFunction(dynFunctions.type(), dynFunctions.function()));
        ruleFunctions.forEach(entry -> planner.evaluationFunction(entry.type, entry.function));

        return policy.accept(planner.build());
    }

    @NotNull
    private Result<Void> failValidator(String type, PolicyValidatorFunction validator, PolicyContext context) {
        return failure(context.hasProblems() ? context.getProblems() : List.of(type + " failed: " + validator.getClass().getName()));
    }

    private record ConstraintFunction<R extends Rule, C extends PolicyContext>(
            Class<R> type,
            String key,
            AtomicConstraintRuleFunction<R, C> function
    ) { }

    private record DynamicConstraintFunction<R extends Rule, C extends PolicyContext>(
            Class<R> type,
            DynamicAtomicConstraintRuleFunction<R, C> function
    ) { }

    private record RuleFunction<R extends Rule, C extends PolicyContext>(
            Class<R> type,
            RulePolicyFunction<R, C> function
    ) { }

}
