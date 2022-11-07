/*
 *  Copyright (c) 2021 - 2022 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *       Fraunhofer Institute for Software and Systems Engineering - Improvements
 *       Microsoft Corporation - Use IDS Webhook address for JWT audience claim
 *
 */

package org.eclipse.edc.iam.did.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import org.eclipse.edc.iam.did.crypto.key.KeyConverter;
import org.eclipse.edc.iam.did.spi.credentials.CredentialsVerifier;
import org.eclipse.edc.iam.did.spi.document.DidConstants;
import org.eclipse.edc.iam.did.spi.document.DidDocument;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.iam.did.spi.key.PrivateKeyWrapper;
import org.eclipse.edc.iam.did.spi.resolution.DidResolverRegistry;
import org.eclipse.edc.jwt.TokenGenerationServiceImpl;
import org.eclipse.edc.jwt.TokenValidationRulesRegistryImpl;
import org.eclipse.edc.jwt.TokenValidationServiceImpl;
import org.eclipse.edc.jwt.spi.JwtDecorator;
import org.eclipse.edc.jwt.spi.TokenValidationRule;
import org.eclipse.edc.jwt.spi.TokenValidationRulesRegistry;
import org.eclipse.edc.spi.iam.ClaimToken;
import org.eclipse.edc.spi.iam.IdentityService;
import org.eclipse.edc.spi.iam.PublicKeyResolver;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.text.ParseException;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.AUDIENCE;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.EXPIRATION_TIME;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.ISSUER;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.JWT_ID;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.SUBJECT;

public class DecentralizedIdentityService implements IdentityService {
    private final DidResolverRegistry resolverRegistry;
    private final CredentialsVerifier credentialsVerifier;
    private final Monitor monitor;
    private final String issuer;
    private final Clock clock;
    private final TokenGenerationServiceImpl tokenGenerationService;

    public DecentralizedIdentityService(DidResolverRegistry resolverRegistry, CredentialsVerifier credentialsVerifier, Monitor monitor, PrivateKeyWrapper privateKey, String issuer, Clock clock) {
        this.resolverRegistry = resolverRegistry;
        this.credentialsVerifier = credentialsVerifier;
        this.monitor = monitor;
        this.issuer = issuer;
        this.clock = clock;
        this.tokenGenerationService = new TokenGenerationServiceImpl(privateKey.signer());
    }

    /** TODO: update documentation
     * Creates a signed JWT {@link SignedJWT} that contains a set of claims and an issuer. Although all private key types are possible, in the context of Distributed Identity
     * using an Elliptic Curve key ({@code P-256}) is advisable.
     *
     * @param privateKey A Private Key represented as {@link PrivateKeyWrapper}.
     * @param issuer     the value of the token issuer claim.
     * @param subject    the value of the token subject claim. For Distributed Identity, this value is identical to the issuer claim.
     * @param audience   the value of the token audience claim, e.g. the IDS Webhook address.
     * @param clock      clock used to get current time.
     * @return a {@code SignedJWT} that is signed with the private key and contains all claims listed.
     */
    @Override
    public Result<TokenRepresentation> obtainClientCredentials(TokenParameters parameters) {
        var decorator = new JwtDecorator() {
            @Override
            public Map<String, Object> claims() {
                return Map.of(
                        ISSUER, issuer,
                        SUBJECT, issuer,
                        AUDIENCE, List.of(parameters.getAudience()),
                        JWT_ID, UUID.randomUUID().toString(),
                        EXPIRATION_TIME, Date.from(clock.instant().plus(10, ChronoUnit.MINUTES))
                );
            }

            @Override
            public Map<String, Object> headers() {
                return Collections.emptyMap();
            }
        };

        return tokenGenerationService.generate(decorator);
    }

    @Override
    public Result<ClaimToken> verifyJwtToken(TokenRepresentation tokenRepresentation, String audience) {
        return getDidDocument(tokenRepresentation)
                .compose(didDocument -> {
                    var publicKeyResolver = getPublicKeyResolver(didDocument);
                    var rulesRegistry = getTokenValidationRulesRegistry(audience);

                    var validationService = new TokenValidationServiceImpl(publicKeyResolver, rulesRegistry);
                    var result =  validationService.validate(tokenRepresentation);
                    if (result.failed()) {
                        return Result.failure("Failed to validate token: " + result.getFailureDetail());
                    }

                    monitor.debug("verification successful! Fetching data from IdentityHub");
                    return credentialsVerifier.getVerifiedCredentials(didDocument);
                })
                .map(credentials -> ClaimToken.Builder.newInstance()
                        .claims(credentials)
                        .build()
                );
    }

    @NotNull
    private static TokenValidationRulesRegistry getTokenValidationRulesRegistry(String audience) {
        var registry = new TokenValidationRulesRegistryImpl();
        registry.addRule(new DidTokenValidationRule(audience));
        return registry;
    }

    @NotNull
    private PublicKeyResolver getPublicKeyResolver(DidDocument didDocument) {
        return id -> {
            try {
                var publicKey = getPublicKey(didDocument);
                if (publicKey.isEmpty()) {
                    return null;
                }

                var verificationMethod = publicKey.get();
                return KeyConverter.toPublicKey(verificationMethod.getPublicKeyJwk(), verificationMethod.getId()).toPublicKey();
            } catch (Exception e) {
                return null;
            }

        };
    }

    private Result<DidDocument> getDidDocument(TokenRepresentation tokenRepresentation) {
        try {
            monitor.debug("Starting verification...");
            var jwt = SignedJWT.parse(tokenRepresentation.getToken());

            monitor.debug("Resolving other party's DID Document");
            return resolverRegistry.resolve(jwt.getJWTClaimsSet().getIssuer());
        } catch (ParseException e) {
            monitor.severe("Cannot get DidDocument out of the token", e);
            return Result.failure("Cannot get DidDocument out of the token: " + e.getMessage());
        }
    }

    @NotNull
    private Optional<VerificationMethod> getPublicKey(DidDocument did) {
        return did.getVerificationMethod().stream().filter(vm -> DidConstants.ALLOWED_VERIFICATION_TYPES.contains(vm.getType())).findFirst();
    }

    private static class DidTokenValidationRule implements TokenValidationRule {
        private final String audience;

        public DidTokenValidationRule(String audience) {
            this.audience = audience;
        }

        @Override
        public Result<Void> checkRule(@NotNull ClaimToken toVerify, @Nullable Map<String, Object> additional) {
            var builder = new JWTClaimsSet.Builder();
            toVerify.getClaims().forEach(builder::claim);
            var exactMatchClaims = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .build();
            var requiredClaims = Set.of(ISSUER, SUBJECT, EXPIRATION_TIME);

            var claimsVerifier = new DefaultJWTClaimsVerifier<>(exactMatchClaims, requiredClaims);
            try {
                claimsVerifier.verify(builder.build());
            } catch (BadJWTException e) {
                return Result.failure("Claim verification failed. " + e.getMessage());
            }

            return Result.success();
        }
    }
}
