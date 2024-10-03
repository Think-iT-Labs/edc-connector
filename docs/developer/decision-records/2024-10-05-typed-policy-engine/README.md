# Typed Policy Engine

## Decision

We will implement a new implementation of the Policy Engine, with strongly typed scopes and contexts.

## Rationale

At the moment implementing a new policy function for an adopter requires a "blind guess" about the content of the `PolicyContext`
object, because it's designed as an unstructured map. 
Bounding the context structure to the scope will help documentation and usability of the Policy Engine. 

## Approach

First we need to make two assumptions:
- it won't be possible to register a policy function or a policy validator under `ALL_SCOPES` (`*`):
    - it makes no sense to have a function/validator bound to all the scopes, scopes have well defined bound, they could
      share context content (e.g. `Instant now` field could be one of them), but this should happen at the `PolicyContext`
      hierarchy level.
- scope hierarchy won't be a thing anymore (e.g. `scope` and `scope.child`)
  - for the same reason as before, plus, it is a feature never really used, because an actual scope hierarchy was never 
    defined.

We will define a `record` that will represent the scope:
```java
public record PolicyScope<C extends PolicyContext>(String name) { }
```
The record is bound to a `PolicyContext` context implementation, and it has a `name` property.

The biggest part of refactor evolves around extracting a `ScopedPolicyEngine` from `PolicyEngine`, that will work only on a specific
scope, the interface will be pretty similar to the `PolicyEngine` one, but it won't need to have the `scope` passed, because
that will be an internal attribute.

e.g.
```java
public interface ScopedPolicyEngine<C extends PolicyContext> {

    Result<Void> evaluate(Policy policy, C context);

    Policy filter(Policy policy);

    <R extends Rule> void registerFunction(Class<R> type, String key, AtomicConstraintRuleFunction<R, C> function);

    <R extends Rule> void registerFunction(Class<R> type, DynamicAtomicConstraintRuleFunction<R, C> function);

    <R extends Rule> void registerFunction(Class<R> type, RulePolicyFunction<R, C> function);

    void registerPreValidator(PolicyValidatorFunction validator);

    void registerPostValidator(PolicyValidatorFunction validator);

    PolicyEvaluationPlan createEvaluationPlan(Policy policy);

}
```

this `ScopedPolicyEngine` can then be obtained from the `PolicyEngine`:
```java
public interface PolicyEngine {
    ...

    <C extends PolicyContext, S extends PolicyScope<C>> ScopedPolicyEngine<C> forScope(S scope);
    
    ...
```

All the `PolicyEngine` methods with `String scope` will be deprecated, and the implementation will call `forScope` internally
to avoid breaking changes.

Other interfaces/classes will need to be duplicated with a "scoped" version of them, like: 
- `AtomicConstraintFunction`
- `DynamicAtomicConstraintFunction`
- `RuleFunction`
- ...

The `PolicyEvaluationPlanner` and the related "steps" will need to be adapted to the new interfaces, no need to do with
duplicate/deprecate because is an internal component.