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

import org.eclipse.edc.policy.engine.spi.AtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.DynamicAtomicConstraintRuleFunction;
import org.eclipse.edc.policy.engine.spi.PolicyContext;
import org.eclipse.edc.policy.engine.spi.PolicyContextImpl;
import org.eclipse.edc.policy.engine.spi.PolicyScope;
import org.eclipse.edc.policy.engine.spi.PolicyValidatorFunction;
import org.eclipse.edc.policy.engine.spi.RuleBindingRegistry;
import org.eclipse.edc.policy.engine.spi.RulePolicyFunction;
import org.eclipse.edc.policy.engine.spi.ScopedPolicyEngine;
import org.eclipse.edc.policy.engine.spi.plan.PolicyEvaluationPlan;
import org.eclipse.edc.policy.engine.spi.plan.step.AtomicConstraintStep;
import org.eclipse.edc.policy.engine.spi.plan.step.DutyStep;
import org.eclipse.edc.policy.engine.spi.plan.step.MultiplicityConstraintStep;
import org.eclipse.edc.policy.engine.spi.plan.step.PermissionStep;
import org.eclipse.edc.policy.engine.spi.plan.step.ProhibitionStep;
import org.eclipse.edc.policy.engine.spi.plan.step.RuleStep;
import org.eclipse.edc.policy.engine.spi.plan.step.ValidatorStep;
import org.eclipse.edc.policy.engine.validation.RuleValidator;
import org.eclipse.edc.policy.model.Action;
import org.eclipse.edc.policy.model.AndConstraint;
import org.eclipse.edc.policy.model.AtomicConstraint;
import org.eclipse.edc.policy.model.Duty;
import org.eclipse.edc.policy.model.LiteralExpression;
import org.eclipse.edc.policy.model.OrConstraint;
import org.eclipse.edc.policy.model.Permission;
import org.eclipse.edc.policy.model.Policy;
import org.eclipse.edc.policy.model.Prohibition;
import org.eclipse.edc.policy.model.Rule;
import org.eclipse.edc.policy.model.XoneConstraint;
import org.eclipse.edc.spi.result.Result;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.junit.assertions.AbstractResultAssert.assertThat;
import static org.eclipse.edc.policy.engine.spi.PolicyEngine.ALL_SCOPES;
import static org.eclipse.edc.policy.model.Operator.EQ;
import static org.junit.jupiter.params.provider.Arguments.of;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ScopedPolicyEngineImplTest {

    private static final String TEST_SCOPE = "test";
    private final RuleBindingRegistry bindingRegistry = new RuleBindingRegistryImpl();
    private ScopedPolicyEngine<TestContext> policyEngine;


    @BeforeEach
    void setUp() {
        var scopeFilter = new ScopeFilter(bindingRegistry);
        var ruleValidator = new RuleValidator(bindingRegistry);
        policyEngine = new ScopedPolicyEngineImpl<>(new PolicyScope<>(TEST_SCOPE), scopeFilter, ruleValidator);
    }

    @Nested
    class Evaluate {
        @Test
        void validateEmptyPolicy() {
            var context = new TestContext();
            var emptyPolicy = Policy.Builder.newInstance().build();

            var result = policyEngine.evaluate(emptyPolicy, context);

            assertThat(result).isSucceeded();
        }

        @Test
        void validateUnsatisfiedDuty() {
            bindingRegistry.bind("foo", ALL_SCOPES);
            var context = new TestContext();

            policyEngine.registerFunction(Duty.class, "foo", (op, rv, duty, ctx) -> false);

            var constraint = AtomicConstraint.Builder.newInstance()
                    .leftExpression(new LiteralExpression("foo"))
                    .operator(EQ)
                    .rightExpression(new LiteralExpression("bar"))
                    .build();
            var duty = Duty.Builder.newInstance().constraint(constraint).build();
            var policy = Policy.Builder.newInstance().duty(duty).build();

            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @Test
        void validateRuleOutOfScope() {
            // Verifies that a rule will be filtered if its action is not registered. The constraint is registered but it
            // should be filtered since it is contained in the permission.
            // If the permission is not properly filtered, the constraint will not be fulfilled and raise an exception.
            bindingRegistry.bind("foo", ALL_SCOPES);
            var context = new TestContext();

            var left = new LiteralExpression("foo");
            var right = new LiteralExpression("bar");
            var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();

            var action = Action.Builder.newInstance().type("OUT_OF_SCOPE").build();
            var permission = Permission.Builder.newInstance().action(action).constraint(constraint).build();
            var policy = Policy.Builder.newInstance().permission(permission).build();

            // the permission containing the unfulfilled constraint should be filtered, resulting in the policy evaluation succeeding
            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isSucceeded();
        }

        @Test
        void validateUngrantedPermission() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            policyEngine.registerFunction(Permission.class, "foo", (op, rv, duty, context) -> false);
            var context = new TestContext();

            var left = new LiteralExpression("foo");
            var right = new LiteralExpression("bar");
            var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
            var permission = Permission.Builder.newInstance().constraint(constraint).build();
            var policy = Policy.Builder.newInstance().permission(permission).build();

            // The permission is not granted, so the policy should evaluate to false
            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @Test
        void validateTriggeredProhibition() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            policyEngine.registerFunction(Prohibition.class, "foo", (op, rv, duty, context) -> true);
            var context = new TestContext();

            var policy = createTestPolicy();

            // The prohibition is triggered (it is true), so the policy should evaluate to false
            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @Test
        void validateChildScopeNotVisible() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            policyEngine.registerFunction(Prohibition.class, "foo", (op, rv, duty, context) -> true);
            var context = new TestContext();

            var policy = createTestPolicy();

            // The bar-scoped prohibition is triggered (it is true), so the policy should evaluate to false
            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @Test
        void validateRuleFunctionOutOfScope() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            var action = Action.Builder.newInstance().type("use").build();
            var permission = Permission.Builder.newInstance().action(action).build();
            var policy = Policy.Builder.newInstance().permission(permission).build();
            var context = new TestContext();

            policyEngine.registerFunction(Permission.class, (rule, ctx) -> rule.getAction().getType().equals(action.getType()));

            assertThat(policyEngine.evaluate(policy, context)).isSucceeded();
        }
    }

    @Nested
    class PrePostValidators {

        @Test
        void validateAllScopesPreFunctionalValidator() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            policyEngine.registerPreValidator((p, c) -> false);

            var policy = Policy.Builder.newInstance().build();
            var context = new TestContext();

            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @Test
        void validateAllScopesPostFunctionalValidator() {
            bindingRegistry.bind("foo", ALL_SCOPES);

            policyEngine.registerPostValidator((p, c) -> false);

            var policy = Policy.Builder.newInstance().build();
            var context = new TestContext();

            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }


        @ParameterizedTest
        @ValueSource(booleans = { true, false })
        void validateAllScopesPrePostValidator(boolean preValidation) {
            bindingRegistry.bind("foo", ALL_SCOPES);

            if (preValidation) {
                policyEngine.registerPreValidator((policy, context) -> false);
            } else {
                policyEngine.registerPostValidator((policy, context) -> false);
            }
            var policy = Policy.Builder.newInstance().build();
            var context = new TestContext();

            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

        @ParameterizedTest
        @ValueSource(booleans = { true, false })
        void validateScopedPrePostValidator(boolean preValidation) {
            bindingRegistry.bind("foo", TEST_SCOPE);

            if (preValidation) {
                policyEngine.registerPreValidator((policy, context) -> false);
            } else {
                policyEngine.registerPostValidator((policy, context) -> false);
            }

            var policy = Policy.Builder.newInstance().build();
            var context = new TestContext();

            var result = policyEngine.evaluate(policy, context);

            assertThat(result).isFailed();
        }

    }

    @Nested
    class DynamicFunction {
        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void shouldTriggerDynamicFunction_whenExplicitScope(Policy policy, Class<Rule> ruleClass, boolean evaluateReturn) {
            bindingRegistry.dynamicBind((key) -> Set.of(TEST_SCOPE));

            var context = new TestContext();
            DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();
            policyEngine.registerFunction(ruleClass, function);

            when(function.canHandle(any())).thenReturn(true);
            when(function.evaluate(any(), any(), any(), any(), eq(context))).thenReturn(evaluateReturn);

            var result = policyEngine.evaluate(policy, context);

            assertThat(result.succeeded()).isTrue();

            verify(function).canHandle(any());
            verify(function).evaluate(any(), any(), any(), any(), eq(context));
        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void shouldNotTriggerDynamicFunction_whenBindAlreadyAvailable(Policy policy, Class<Rule> ruleClass) {
            bindingRegistry.bind("foo", ALL_SCOPES);
            policyEngine.registerFunction(ruleClass, "foo", (op, rv, duty, context) -> !ruleClass.isAssignableFrom(Prohibition.class));
            bindingRegistry.dynamicBind((key) -> Set.of(TEST_SCOPE));

            var context = new TestContext();
            DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();
            policyEngine.registerFunction(ruleClass, function);

            var result = policyEngine.evaluate(policy, context);

            assertThat(result.succeeded()).isTrue();

            verifyNoInteractions(function);
        }

        private static class PolicyProvider implements ArgumentsProvider {
            @Override
            public Stream<? extends Arguments> provideArguments(ExtensionContext context) {

                var left = new LiteralExpression("foo");
                var right = new LiteralExpression("bar");
                var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
                var prohibition = Prohibition.Builder.newInstance().constraint(constraint).build();
                var permission = Permission.Builder.newInstance().constraint(constraint).build();
                var duty = Duty.Builder.newInstance().constraint(constraint).build();

                return Stream.of(
                        of(Policy.Builder.newInstance().permission(permission).build(), Permission.class, true),
                        of(Policy.Builder.newInstance().duty(duty).build(), Duty.class, true),
                        of(Policy.Builder.newInstance().prohibition(prohibition).build(), Prohibition.class, false)
                );
            }
        }
    }

    @Nested
    class CreateEvaluationPlan {

        @Nested
        class EvaluationPlan {

            @ParameterizedTest
            @ArgumentsSource(SimplePolicyProvider.class)
            void withRule(Policy policy, Class<Rule> ruleClass, String action, String key, Function<PolicyEvaluationPlan, List<RuleStep<? extends Rule>>> stepsProvider) {

                bindingRegistry.bind(action, TEST_SCOPE);
                bindingRegistry.bind(key, TEST_SCOPE);

                policyEngine.registerFunction(ruleClass, key, (op, rv, r, ctx) -> true);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(stepsProvider.apply(plan)).hasSize(1)
                        .first()
                        .satisfies(ruleStep -> {
                            assertThat(ruleStep.isFiltered()).isFalse();
                            assertThat(ruleStep.getRuleFunctions()).hasSize(0);
                            assertThat(ruleStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, (constraintStep) -> {
                                        assertThat(constraintStep.isFiltered()).isFalse();
                                        assertThat(constraintStep.functionName()).isNotNull();
                                        assertThat(constraintStep.constraint()).isNotNull();
                                        assertThat(constraintStep.rule()).isInstanceOf(ruleClass);
                                    });
                        });
            }

            @ParameterizedTest
            @ArgumentsSource(SimplePolicyProvider.class)
            void withRuleAndDynFunction(Policy policy, Class<Rule> ruleClass, String action, String key, Function<PolicyEvaluationPlan, List<RuleStep<? extends Rule>>> stepsProvider) {

                DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();

                when(function.canHandle(key)).thenReturn(true);
                when(function.name()).thenReturn("functionName");

                bindingRegistry.bind(action, TEST_SCOPE);
                bindingRegistry.bind(key, TEST_SCOPE);

                policyEngine.registerFunction(ruleClass, function);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(stepsProvider.apply(plan)).hasSize(1)
                        .first()
                        .satisfies(ruleStep -> {
                            assertThat(ruleStep.isFiltered()).isFalse();
                            assertThat(ruleStep.getRuleFunctions()).hasSize(0);
                            assertThat(ruleStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, (constraintStep) -> {
                                        assertThat(constraintStep.isFiltered()).isFalse();
                                        assertThat(constraintStep.functionName()).isEqualTo("functionName");
                                        assertThat(constraintStep.constraint()).isNotNull();
                                        assertThat(constraintStep.rule()).isInstanceOf(ruleClass);
                                    });
                        });
            }


            @ParameterizedTest
            @ArgumentsSource(SimplePolicyProvider.class)
            void withRuleAndRuleFunction(Policy policy, Class<Rule> ruleClass, String action, String key, Function<PolicyEvaluationPlan, List<RuleStep<? extends Rule>>> stepsProvider) {

                RulePolicyFunction<Rule, TestContext> function = mock();
                RulePolicyFunction<Rule, TestContext> anotherFunction = mock();

                bindingRegistry.bind(action, TEST_SCOPE);
                bindingRegistry.bind(key, TEST_SCOPE);

                policyEngine.registerFunction(ruleClass, function);
                policyEngine.registerFunction(ruleClass, anotherFunction);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(stepsProvider.apply(plan)).hasSize(1)
                        .first()
                        .satisfies(ruleStep -> {
                            assertThat(ruleStep.isFiltered()).isFalse();
                            assertThat(ruleStep.getRuleFunctions()).hasSize(2);
                            assertThat(ruleStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, (constraintStep) -> {
                                        assertThat(constraintStep.isFiltered()).isTrue();
                                        assertThat(constraintStep.functionName()).isNull();
                                        assertThat(constraintStep.constraint()).isNotNull();
                                        assertThat(constraintStep.rule()).isInstanceOf(ruleClass);
                                    });
                        });
            }

            @Test
            void withPermissionContainingDuty() {

                var key = "foo";
                var actionType = "action";
                var constraint = atomicConstraint(key, "bar");
                var action = Action.Builder.newInstance().type(actionType).build();
                var duty = Duty.Builder.newInstance().constraint(constraint).action(action).build();
                var permission = Permission.Builder.newInstance().constraint(constraint).duty(duty).action(action).build();
                var policy = Policy.Builder.newInstance().permission(permission).build();

                bindingRegistry.bind(actionType, TEST_SCOPE);
                bindingRegistry.bind(key, TEST_SCOPE);

                policyEngine.registerFunction(Duty.class, key, (op, rv, r, ctx) -> true);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPermissionSteps()).hasSize(1)
                        .first()
                        .satisfies(ruleStep -> {
                            assertThat(ruleStep.isFiltered()).isFalse();
                            assertThat(ruleStep.getDutySteps()).hasSize(1);
                            assertThat(ruleStep.getRuleFunctions()).hasSize(0);
                            assertThat(ruleStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.isFiltered()).isTrue();
                                        assertThat(constraintStep.functionName()).isNull();
                                        assertThat(constraintStep.constraint()).isNotNull();
                                        assertThat(constraintStep.rule()).isInstanceOf(Permission.class);
                                    });
                        });
            }


            private static class SimplePolicyProvider implements ArgumentsProvider {
                @Override
                public Stream<? extends Arguments> provideArguments(ExtensionContext context) {

                    var leftOperand = "foo";
                    var actionType = "action";

                    var action = Action.Builder.newInstance().type(actionType).build();
                    var constraint = atomicConstraint(leftOperand, "bar");

                    var prohibition = Prohibition.Builder.newInstance().constraint(constraint).action(action).build();

                    Function<PolicyEvaluationPlan, List<PermissionStep>> permissionSteps = PolicyEvaluationPlan::getPermissionSteps;
                    Function<PolicyEvaluationPlan, List<DutyStep>> dutySteps = PolicyEvaluationPlan::getObligationSteps;
                    Function<PolicyEvaluationPlan, List<ProhibitionStep>> prohibitionSteps = PolicyEvaluationPlan::getProhibitionSteps;

                    var permission = Permission.Builder.newInstance().constraint(constraint).action(action).build();
                    var duty = Duty.Builder.newInstance().constraint(constraint).action(action).build();

                    return Stream.of(
                            of(Policy.Builder.newInstance().permission(permission).build(), Permission.class, actionType, leftOperand, permissionSteps),
                            of(Policy.Builder.newInstance().duty(duty).build(), Duty.class, actionType, leftOperand, dutySteps),
                            of(Policy.Builder.newInstance().prohibition(prohibition).build(), Prohibition.class, actionType, leftOperand, prohibitionSteps)
                    );
                }
            }
        }

        @Nested
        class IgnoredStep {

            @Test
            void shouldIgnorePermissionStep_whenActionNotBound() {

                bindingRegistry.bind("foo", TEST_SCOPE);

                var constraint = atomicConstraint("foo", "bar");

                var permission = Permission.Builder.newInstance().action(Action.Builder.newInstance().type("action").build()).constraint(constraint).build();
                var policy = Policy.Builder.newInstance().permission(permission).build();
                policyEngine.registerFunction(Permission.class, "foo", (op, rv, r, ctx) -> true);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPermissionSteps()).hasSize(1)
                        .first()
                        .satisfies(permissionStep -> {
                            assertThat(permissionStep.isFiltered()).isTrue();
                            assertThat(permissionStep.getFilteringReasons()).hasSize(1);
                            assertThat(permissionStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.isFiltered()).isFalse();
                                    });
                        });
            }

            @Test
            void shouldIgnoreAtomicConstraintStep_whenLeftExpressionNotScopeBound() {

                bindingRegistry.bind("action", TEST_SCOPE);

                var constraint = atomicConstraint("foo", "bar");
                var permission = Permission.Builder.newInstance().action(Action.Builder.newInstance().type("action").build()).constraint(constraint).build();
                var policy = Policy.Builder.newInstance().permission(permission).build();

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPermissionSteps()).hasSize(1)
                        .first()
                        .satisfies(permissionStep -> {
                            assertThat(permissionStep.isFiltered()).isFalse();
                            assertThat(permissionStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.isFiltered()).isTrue();
                                    });
                        });
            }

            @Test
            void shouldIgnoreAtomicConstraintStep_whenLeftExpressionNotFunctionBound() {

                bindingRegistry.bind("action", TEST_SCOPE);
                bindingRegistry.bind("foo", TEST_SCOPE);

                var constraint = atomicConstraint("foo", "bar");
                var permission = Permission.Builder.newInstance().action(Action.Builder.newInstance().type("action").build()).constraint(constraint).build();
                var policy = Policy.Builder.newInstance().permission(permission).build();

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPermissionSteps()).hasSize(1)
                        .first()
                        .satisfies(permissionStep -> {
                            assertThat(permissionStep.isFiltered()).isFalse();
                            assertThat(permissionStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.isFiltered()).isTrue();
                                    });
                        });
            }

            @Test
            void shouldIgnoreAtomicConstraintStep_whenLeftExpressionNotDynFunctionBound() {


                DynamicAtomicConstraintRuleFunction<Duty, TestContext> function = mock();

                when(function.canHandle(any())).thenReturn(true);

                bindingRegistry.bind("action", TEST_SCOPE);
                bindingRegistry.bind("foo", TEST_SCOPE);

                var constraint = atomicConstraint("foo", "bar");
                var permission = Permission.Builder.newInstance().action(Action.Builder.newInstance().type("action").build()).constraint(constraint).build();
                var policy = Policy.Builder.newInstance().permission(permission).build();
                policyEngine.registerFunction(Duty.class, function);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPermissionSteps()).hasSize(1)
                        .first()
                        .satisfies(permissionStep -> {
                            assertThat(permissionStep.isFiltered()).isFalse();
                            assertThat(permissionStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(AtomicConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.isFiltered()).isTrue();
                                        assertThat(constraintStep.functionName()).isNull();
                                    });
                        });
            }

        }

        @Nested
        class MultiplicityConstraints {

            @ParameterizedTest
            @ArgumentsSource(MultiplicityPolicyProvider.class)
            void shouldEvaluate_withMultiplicityConstraint(Policy policy, Class<Rule> ruleClass, String action, String key, Function<PolicyEvaluationPlan, List<RuleStep<? extends Rule>>> stepsProvider) {

                bindingRegistry.bind(key, TEST_SCOPE);
                bindingRegistry.bind(action, TEST_SCOPE);

                policyEngine.registerFunction(ruleClass, key, (op, rv, r, ctx) -> true);

                var plan = policyEngine.createEvaluationPlan(policy);

                assertThat(plan.getPreValidators()).isEmpty();
                assertThat(plan.getPostValidators()).isEmpty();


                assertThat(stepsProvider.apply(plan)).hasSize(1)
                        .first()
                        .satisfies((ruleStep -> {
                            assertThat(ruleStep.isFiltered()).isFalse();
                            assertThat(ruleStep.getConstraintSteps()).hasSize(1)
                                    .first()
                                    .isInstanceOfSatisfying(MultiplicityConstraintStep.class, constraintStep -> {
                                        assertThat(constraintStep.getConstraintSteps()).hasSize(2);
                                        assertThat(constraintStep.getConstraint()).isNotNull();
                                    });
                        }));

            }

            private static class MultiplicityPolicyProvider implements ArgumentsProvider {
                @Override
                public Stream<? extends Arguments> provideArguments(ExtensionContext context) {

                    var leftOperand = "foo";
                    var actionType = "action";

                    var firstConstraint = atomicConstraint("foo", "bar");
                    var secondConstraint = atomicConstraint("baz", "bar");

                    var orConstraints = OrConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();
                    var andConstraints = AndConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();
                    var xoneConstraint = XoneConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();

                    var permission = Permission.Builder.newInstance().constraint(andConstraints).build();
                    var prohibition = Prohibition.Builder.newInstance().constraint(orConstraints).build();
                    var duty = Duty.Builder.newInstance().constraint(xoneConstraint).build();

                    Function<PolicyEvaluationPlan, List<PermissionStep>> permissionSteps = PolicyEvaluationPlan::getPermissionSteps;
                    Function<PolicyEvaluationPlan, List<DutyStep>> dutySteps = PolicyEvaluationPlan::getObligationSteps;
                    Function<PolicyEvaluationPlan, List<ProhibitionStep>> prohibitionSteps = PolicyEvaluationPlan::getProhibitionSteps;

                    return Stream.of(
                            of(Policy.Builder.newInstance().permission(permission).build(), Permission.class, actionType, leftOperand, permissionSteps),
                            of(Policy.Builder.newInstance().duty(duty).build(), Duty.class, actionType, leftOperand, dutySteps),
                            of(Policy.Builder.newInstance().prohibition(prohibition).build(), Prohibition.class, actionType, leftOperand, prohibitionSteps)
                    );
                }
            }
        }

        @Nested
        class Validator {

            @Test
            void shouldEvaluate_withNoValidators() {
                var emptyPolicy = Policy.Builder.newInstance().build();

                var plan = policyEngine.createEvaluationPlan(emptyPolicy);

                assertThat(plan.getPostValidators()).isEmpty();
                assertThat(plan.getPreValidators()).isEmpty();
            }

            @Test
            void shouldEvaluate_withFunctionalValidators() {
                var emptyPolicy = Policy.Builder.newInstance().build();

                PolicyValidatorFunction function = (policy, policyContext) -> true;
                policyEngine.registerPreValidator(function);
                policyEngine.registerPostValidator(function);

                var plan = policyEngine.createEvaluationPlan(emptyPolicy);

                assertThat(plan.getPreValidators()).hasSize(1)
                        .extracting(ValidatorStep::name)
                        .allMatch(s -> s.contains(getClass().getSimpleName()));

                assertThat(plan.getPostValidators()).hasSize(1)
                        .extracting(ValidatorStep::name)
                        .allMatch(s -> s.contains(getClass().getSimpleName()));

            }

            @Test
            void shouldEvaluate_withValidators() {
                var emptyPolicy = Policy.Builder.newInstance().build();
                policyEngine.registerPreValidator(new Validator.MyValidatorFunction());
                policyEngine.registerPostValidator(new Validator.MyValidatorFunction());

                var plan = policyEngine.createEvaluationPlan(emptyPolicy);

                assertThat(plan.getPreValidators()).hasSize(1)
                        .extracting(ValidatorStep::name)
                        .contains("MyCustomValidator");
                assertThat(plan.getPostValidators()).hasSize(1)
                        .extracting(ValidatorStep::name)
                        .contains("MyCustomValidator");

            }

            static class MyValidatorFunction implements PolicyValidatorFunction {

                @Override
                public Boolean apply(Policy policy, PolicyContext policyContext) {
                    return true;
                }

                @Override
                public String name() {
                    return "MyCustomValidator";
                }
            }
        }

        private static AtomicConstraint atomicConstraint(String key, String value) {
            var left = new LiteralExpression(key);
            var right = new LiteralExpression(value);
            return AtomicConstraint.Builder.newInstance()
                    .leftExpression(left)
                    .operator(EQ)
                    .rightExpression(right)
                    .build();
        }
    }

    @Nested
    class Validate {

        @Test
        void validateEmptyPolicy() {
            var emptyPolicy = Policy.Builder.newInstance().build();

            var result = policyEngine.validate(emptyPolicy);

            assertThat(result).isSucceeded();
        }

        @Test
        void validate_whenKeyNotBoundInTheRegistryAndToFunctions() {

            var left = new LiteralExpression("foo");
            var right = new LiteralExpression("bar");
            var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
            var permission = Permission.Builder.newInstance().constraint(constraint).build();
            var policy = Policy.Builder.newInstance().permission(permission).build();
            policyEngine.registerFunction(Duty.class, "foo", (op, rv, r, ctx) -> true);
            policyEngine.registerFunction(Prohibition.class, "foo", (op, rv, r, ctx) -> true);

            var result = policyEngine.validate(policy);

            // The foo key is not bound nor to function nor in the RuleBindingRegistry
            assertThat(result).isFailed().messages().hasSize(2)
                    .anyMatch(s -> s.startsWith("leftOperand 'foo' is not bound to any scopes"))
                    .anyMatch(s -> s.startsWith("left operand 'foo' is not bound to any functions"));

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate_whenKeyIsNotBoundInTheRegistry(Policy policy, Class<Rule> ruleClass, String key) {

            policyEngine.registerFunction(ruleClass, key, (op, rv, duty, ctx) -> true);

            var result = policyEngine.validate(policy);

            // The input key is not bound in the RuleBindingRegistry
            assertThat(result).isFailed().messages().hasSize(1)
                    .anyMatch(s -> s.startsWith("leftOperand '%s' is not bound to any scopes".formatted(key)));

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate(Policy policy, Class<Rule> ruleClass, String key) {


            bindingRegistry.bind(key, ALL_SCOPES);
            policyEngine.registerFunction(ruleClass, key, (op, rv, duty, ctx) -> true);

            var result = policyEngine.validate(policy);

            assertThat(result).isSucceeded();

        }

        @Test
        void validate_shouldFail_withDynamicFunction() {

            var leftOperand = "foo";
            var left = new LiteralExpression(leftOperand);
            var right = new LiteralExpression("bar");
            var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
            var permission = Permission.Builder.newInstance().constraint(constraint).action(Action.Builder.newInstance().type("use").build()).build();

            var policy = Policy.Builder.newInstance().permission(permission).build();

            DynamicAtomicConstraintRuleFunction<Duty, TestContext> function = mock();

            when(function.canHandle(leftOperand)).thenReturn(true);

            when(function.validate(any(), any(), any(), any())).thenReturn(Result.success());

            bindingRegistry.dynamicBind(s -> Set.of(ALL_SCOPES));
            policyEngine.registerFunction(Duty.class, function);

            var result = policyEngine.validate(policy);

            assertThat(result).isFailed()
                    .messages()
                    .anyMatch(s -> s.startsWith("left operand '%s' is not bound to any functions".formatted(leftOperand)));

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate_withDynamicFunction(Policy policy, Class<Rule> ruleClass, String key) {

            DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();

            when(function.canHandle(key)).thenReturn(true);
            when(function.validate(any(), any(), any(), any())).thenReturn(Result.success());

            bindingRegistry.dynamicBind(s -> Set.of(ALL_SCOPES));
            policyEngine.registerFunction(ruleClass, function);

            var result = policyEngine.validate(policy);

            assertThat(result).isSucceeded();

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate_shouldFail_whenSkippingDynamicFunction(Policy policy, Class<Rule> ruleClass, String key) {

            DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();

            when(function.canHandle(key)).thenReturn(false);

            bindingRegistry.dynamicBind(s -> Set.of(ALL_SCOPES));
            policyEngine.registerFunction(ruleClass, function);

            var result = policyEngine.validate(policy);

            // The input key is not bound any functions , the dynamic one cannot handle the input key
            assertThat(result).isFailed().messages().hasSize(1)
                    .anyMatch(s -> s.startsWith("left operand '%s' is not bound to any functions".formatted(key)));

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate_shouldFails_withDynamicFunction(Policy policy, Class<Rule> ruleClass, String key) {

            DynamicAtomicConstraintRuleFunction<Rule, TestContext> function = mock();

            when(function.canHandle(key)).thenReturn(true);

            when(function.validate(any(), any(), any(), any())).thenReturn(Result.failure("Dynamic function validation failure"));

            bindingRegistry.dynamicBind(s -> Set.of(ALL_SCOPES));
            policyEngine.registerFunction(ruleClass, function);

            var result = policyEngine.validate(policy);

            assertThat(result).isFailed().detail().contains("Dynamic function validation failure");

        }


        @ParameterizedTest
        @ArgumentsSource(PolicyProvider.class)
        void validate_shouldFail_whenFunctionValidationFails(Policy policy, Class<Rule> ruleClass, String key) {

            AtomicConstraintRuleFunction<Rule, TestContext> function = mock();

            when(function.validate(any(), any(), any())).thenReturn(Result.failure("Function validation failure"));

            bindingRegistry.bind(key, ALL_SCOPES);
            policyEngine.registerFunction(ruleClass, key, function);

            var result = policyEngine.validate(policy);

            assertThat(result).isFailed().detail().contains("Function validation failure");

        }

        @Test
        void validate_shouldFail_whenActionIsNotBound() {

            var leftOperand = "foo";
            var left = new LiteralExpression(leftOperand);
            var right = new LiteralExpression("bar");
            var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
            var permission = Permission.Builder.newInstance().constraint(constraint).action(Action.Builder.newInstance().type("use").build()).build();

            var policy = Policy.Builder.newInstance().permission(permission).build();
            AtomicConstraintRuleFunction<Permission, TestContext> function = mock();

            when(function.validate(any(), any(), any())).thenReturn(Result.success());

            bindingRegistry.bind("foo", ALL_SCOPES);
            policyEngine.registerFunction(Permission.class, "foo", function);

            var result = policyEngine.validate(policy);

            // The use action is not bound in the RuleBindingRegistry
            assertThat(result).isFailed().detail().contains("action 'use' is not bound to any scopes");

        }

        @ParameterizedTest
        @ArgumentsSource(PolicyWithMultiplicityConstraintProvider.class)
        void validate_withMultiplicityConstraints(Policy policy, Class<Rule> ruleClass, String[] keys) {


            for (var key : keys) {
                bindingRegistry.bind(key, ALL_SCOPES);
                policyEngine.registerFunction(ruleClass, key, (op, rv, duty, ctx) -> true);
            }


            var result = policyEngine.validate(policy);

            assertThat(result).isSucceeded();

        }

        private static class PolicyProvider implements ArgumentsProvider {
            @Override
            public Stream<? extends Arguments> provideArguments(ExtensionContext context) {

                var leftOperand = "foo";
                var left = new LiteralExpression(leftOperand);
                var right = new LiteralExpression("bar");
                var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
                var prohibition = Prohibition.Builder.newInstance().constraint(constraint).build();
                var permission = Permission.Builder.newInstance().constraint(constraint).build();
                var duty = Duty.Builder.newInstance().constraint(constraint).build();

                return Stream.of(
                        of(Policy.Builder.newInstance().permission(permission).build(), Permission.class, leftOperand),
                        of(Policy.Builder.newInstance().duty(duty).build(), Duty.class, leftOperand),
                        of(Policy.Builder.newInstance().prohibition(prohibition).build(), Prohibition.class, leftOperand)
                );
            }
        }

        private static class PolicyWithMultiplicityConstraintProvider implements ArgumentsProvider {
            @Override
            public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
                var keys = new String[]{ "foo", "baz" };
                var firstConstraint = atomicConstraint("foo", "bar");
                var secondConstraint = atomicConstraint("baz", "bar");


                var orConstraints = OrConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();
                var andConstraints = AndConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();
                var xoneConstraint = XoneConstraint.Builder.newInstance().constraint(firstConstraint).constraint(secondConstraint).build();

                var prohibition = Prohibition.Builder.newInstance().constraint(orConstraints).build();
                var permission = Permission.Builder.newInstance().constraint(andConstraints).build();
                var duty = Duty.Builder.newInstance().constraint(xoneConstraint).build();

                return Stream.of(
                        of(Policy.Builder.newInstance().permission(permission).build(), Permission.class, keys),
                        of(Policy.Builder.newInstance().duty(duty).build(), Duty.class, keys),
                        of(Policy.Builder.newInstance().prohibition(prohibition).build(), Prohibition.class, keys)
                );
            }

            private AtomicConstraint atomicConstraint(String key, String value) {
                var left = new LiteralExpression(key);
                var right = new LiteralExpression(value);
                return AtomicConstraint.Builder.newInstance()
                        .leftExpression(left)
                        .operator(EQ)
                        .rightExpression(right)
                        .build();
            }
        }
    }

    private Policy createTestPolicy() {
        var left = new LiteralExpression("foo");
        var right = new LiteralExpression("bar");
        var constraint = AtomicConstraint.Builder.newInstance().leftExpression(left).operator(EQ).rightExpression(right).build();
        var prohibition = Prohibition.Builder.newInstance().constraint(constraint).build();
        return Policy.Builder.newInstance().prohibition(prohibition).build();
    }

    private static class TestContext extends PolicyContextImpl implements PolicyContext {

    }

}
