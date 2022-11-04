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

import com.nimbusds.jose.JOSEException;
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
import org.eclipse.edc.iam.did.spi.key.PublicKeyWrapper;
import org.eclipse.edc.iam.did.spi.resolution.DidResolverRegistry;
import org.eclipse.edc.jwt.TokenGenerationServiceImpl;
import org.eclipse.edc.jwt.spi.JwtDecorator;
import org.eclipse.edc.spi.iam.ClaimToken;
import org.eclipse.edc.spi.iam.IdentityService;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;

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
        try {
            var jwt = SignedJWT.parse(tokenRepresentation.getToken());
            monitor.debug("Starting verification...");

            monitor.debug("Resolving other party's DID Document");
            var didResult = resolverRegistry.resolve(jwt.getJWTClaimsSet().getIssuer());
            if (didResult.failed()) {
                return Result.failure("Unable to resolve DID: " + String.join(", ", didResult.getFailureMessages()));
            }
            monitor.debug("Extracting public key");

            // this will return the _first_ public key entry
            var publicKey = getPublicKey(didResult.getContent());
            if (publicKey.isEmpty()) {
                return Result.failure("Public Key not found in DID Document!");
            }

            //convert the POJO into a usable PK-wrapper:
            var publicKeyJwk = publicKey.get().getPublicKeyJwk();
            var publicKeyWrapper = KeyConverter.toPublicKeyWrapper(publicKeyJwk, publicKey.get().getId());

            monitor.debug("Verifying JWT with public key...");
            var verified = verify(jwt, publicKeyWrapper, audience);
            if (verified.failed()) {
                monitor.debug(() -> "Failure in token verification: " + verified.getFailureDetail());
                return Result.failure("Token could not be verified!");
            }

            monitor.debug("verification successful! Fetching data from IdentityHub");
            var credentialsResult = credentialsVerifier.getVerifiedCredentials(didResult.getContent());
            if (credentialsResult.failed()) {
                monitor.debug(() -> "Failed to retrieve verified credentials: " + credentialsResult.getFailureDetail());
                return Result.failure("Failed to get verifiable credentials: " + credentialsResult.getFailureDetail());
            }

            monitor.debug("Building ClaimToken");
            var tokenBuilder = ClaimToken.Builder.newInstance();
            var claimToken = tokenBuilder.claims(credentialsResult.getContent()).build();

            return Result.success(claimToken);
        } catch (ParseException e) {
            monitor.severe("Error parsing JWT", e);
            return Result.failure("Error parsing JWT");
        }
    }

    @NotNull
    private Optional<VerificationMethod> getPublicKey(DidDocument did) {
        return did.getVerificationMethod().stream().filter(vm -> DidConstants.ALLOWED_VERIFICATION_TYPES.contains(vm.getType())).findFirst();
    }

    /**
     * Verifies a VerifiableCredential using the issuer's public key
     *
     * @param jwt       a {@link SignedJWT} that was sent by the claiming party.
     * @param publicKey The claiming party's public key, passed as a {@link PublicKeyWrapper}
     * @param audience  The intended audience
     * @return true if verified, false otherwise
     */
    private Result<Void> verify(SignedJWT jwt, PublicKeyWrapper publicKey, String audience) {
        // verify JWT signature
        try {
            var verified = jwt.verify(publicKey.verifier());
            if (!verified) {
                return Result.failure("Invalid signature");
            }
        } catch (JOSEException e) {
            return Result.failure("Unable to verify JWT token. " + e.getMessage()); // e.g. the JWS algorithm is not supported
        }

        JWTClaimsSet jwtClaimsSet;
        try {
            jwtClaimsSet = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            return Result.failure("Error verifying JWT token. The payload must represent a valid JSON object and a JWT claims set. " + e.getMessage());
        }

        // verify claims
        var exactMatchClaims = new JWTClaimsSet.Builder()
                .audience(audience)
                .build();
        var requiredClaims = Set.of(ISSUER, SUBJECT, EXPIRATION_TIME);

        var claimsVerifier = new DefaultJWTClaimsVerifier<>(exactMatchClaims, requiredClaims);
        try {
            claimsVerifier.verify(jwtClaimsSet);
        } catch (BadJWTException e) {
            return Result.failure("Claim verification failed. " + e.getMessage());
        }

        return Result.success();
    }
}
