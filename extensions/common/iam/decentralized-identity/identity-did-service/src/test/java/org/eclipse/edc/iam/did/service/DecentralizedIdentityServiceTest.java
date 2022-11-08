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
 *
 */

package org.eclipse.edc.iam.did.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.edc.iam.did.crypto.key.EcPrivateKeyWrapper;
import org.eclipse.edc.iam.did.crypto.key.KeyPairFactory;
import org.eclipse.edc.iam.did.spi.credentials.CredentialsVerifier;
import org.eclipse.edc.iam.did.spi.document.DidDocument;
import org.eclipse.edc.iam.did.spi.document.EllipticCurvePublicKey;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.iam.did.spi.resolution.DidResolverRegistry;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.monitor.ConsoleMonitor;
import org.eclipse.edc.spi.result.AbstractResult;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static java.time.temporal.ChronoUnit.MINUTES;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.junit.testfixtures.TestUtils.getResourceFileContentAsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test the {@link DecentralizedIdentityService} with a key algorithm.
 */
class DecentralizedIdentityServiceTest {

    private static final String DID_DOCUMENT = getResourceFileContentAsString("dids.json");

    private final Instant now = Instant.now();
    private final CredentialsVerifier credentialsVerifierMock = mock(CredentialsVerifier.class);
    private final DidResolverRegistry didResolverRegistryMock = mock(DidResolverRegistry.class);
    private final String didUrl = "random.did.url";
    private EcPrivateKeyWrapper privateKey;

    private DecentralizedIdentityService identityService;

    @BeforeEach
    void setUp() {
        privateKey = new EcPrivateKeyWrapper(getEcKey("private_p256.pem"));
        identityService = new DecentralizedIdentityService(didResolverRegistryMock, credentialsVerifierMock, new ConsoleMonitor(), privateKey, didUrl, Clock.systemUTC());
    }

    @Test
    void generateAndVerifyJwtToken_valid() {
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.success(Map.of("region", "eu")));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument(getEcKey("public_p256.pem"))));
        var tokenParameters = TokenParameters.Builder.newInstance()
                .audience("test-audience")
                .build();

        var result = identityService.obtainClientCredentials(tokenParameters);
        assertThat(result).matches(AbstractResult::succeeded)
                .extracting(AbstractResult::getContent)
                .extracting(TokenRepresentation::getToken)
                .extracting(this::parseToJwt)
                .satisfies(jwt -> {
                    assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(didUrl);
                    assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(didUrl);
                    assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("test-audience");
                    assertThat(jwt.getJWTClaimsSet().getJWTID()).satisfies(UUID::fromString);
                    assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isCloseTo(now.plus(10, MINUTES), 60_000);
                });

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "test-audience");
        assertThat(verificationResult).matches(AbstractResult::succeeded)
                .extracting(AbstractResult::getContent)
                .extracting(it -> it.getClaim("region")).isEqualTo("eu");
    }

    @Test
    void generateAndVerifyJwtToken_wrongPublicKey() {
        var otherKeyPair = getKeyPair();
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.success(Map.of("region", "eu")));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument((ECKey) otherKeyPair.toPublicJWK())));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());

        assertTrue(result.succeeded());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar");
        assertThat(verificationResult).matches(AbstractResult::failed)
                .extracting(AbstractResult::getFailureMessages).asList().contains("Failed to validate token: Token verification failed");
    }

    @Test
    void generateAndVerifyJwtToken_wrongAudience() {
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument(getEcKey("public_p256.pem"))));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar2");
        assertThat(verificationResult).matches(AbstractResult::failed);
    }

    @Test
    void generateAndVerifyJwtToken_getVerifiedCredentialsFailed() {
        var errorMsg = UUID.randomUUID().toString();
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.failure(errorMsg));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument(getEcKey("public_p256.pem"))));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());
        assertTrue(result.succeeded());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar");
        assertThat(verificationResult).matches(AbstractResult::failed)
                .extracting(AbstractResult::getFailureDetail).asString().contains(errorMsg);
    }


    @ParameterizedTest(name = "{2}")
    @ArgumentsSource(ClaimsArgs.class)
    void verifyJwtToken_OnClaims(UnaryOperator<JWTClaimsSet.Builder> builderOperator, boolean expectSuccess, String ignoredName) throws Exception {
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.success(Map.of("region", "eu")));
        when(didResolverRegistryMock.resolve(any())).thenReturn(Result.success(createDidDocument(getEcKey("public_p256.pem"))));
        var tokenParameters = TokenParameters.Builder.newInstance()
                .audience("test-audience")
                .build();
        var result = identityService.obtainClientCredentials(tokenParameters);
        var vc = parseToJwt(result.getContent().getToken());

        var claimsSetBuilder = new JWTClaimsSet.Builder(vc.getJWTClaimsSet());
        var claimsSet = builderOperator.apply(claimsSetBuilder).build();

        var jwt = new SignedJWT(vc.getHeader(), claimsSet);
        jwt.sign(privateKey.signer());

        var representation = TokenRepresentation.Builder.newInstance().token(jwt.serialize()).build();

        var verifyResult = identityService.verifyJwtToken(representation, "test-audience");
        assertThat(verifyResult.succeeded()).isEqualTo(expectSuccess);
    }

    private ECKey getEcKey(String pemFile) {
        try {
            String privateKeyPem = getResourceFileContentAsString(pemFile);
            return (ECKey) JWK.parseFromPEMEncodedObjects(privateKeyPem);
        } catch (Exception e) {
            throw new RuntimeException("ECKey cannot be loaded from " + pemFile, e);
        }
    }

    private TokenParameters defaultTokenParameters() {
        return TokenParameters.Builder.newInstance()
                .scope("Foo")
                .audience("Bar")
                .build();
    }

    private DidDocument createDidDocument(ECKey publicKey) {
        try {
            var did = new ObjectMapper().readValue(DID_DOCUMENT, DidDocument.class);
            did.getVerificationMethod().add(VerificationMethod.Builder.create()
                    .type("JsonWebKey2020")
                    .id("test-key")
                    .publicKeyJwk(new EllipticCurvePublicKey(publicKey.getCurve().getName(), publicKey.getKeyType().toString(), publicKey.getX().toString(), publicKey.getY().toString()))
                    .build());
            return did;
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    @NotNull
    private SignedJWT parseToJwt(String it) {
        try {
            return SignedJWT.parse(it);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    private JWK getKeyPair() {
        return KeyPairFactory.generateKeyPairP256();
    }

    private static class ClaimsArgs implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    jwtCase(b -> b, true, "valid token"),
                    jwtCase(b -> b.audience(List.of()), false, "empty audience"),
                    jwtCase(b -> b.audience(List.of("https://otherserver.com")), false, "wrong audience"),
                    jwtCase(b -> b.audience(List.of("test-audience")), true, "expected audience"), // sanity check
                    jwtCase(b -> b.subject(null), false, "empty subject"),
                    jwtCase(b -> b.subject("a-subject"), true, "expected subject"), // sanity check
                    jwtCase(b -> b.issuer(null), false, "empty issuer"),
                    jwtCase(b -> b.issuer("other-issuer"), true, "other issuer"),
                    jwtCase(b -> b.expirationTime(null), false, "empty expiration"),
                    // Nimbus library allows (by default) max 60 seconds of expiration date clock skew
                    jwtCase(b -> b.expirationTime(Date.from(Instant.now().minus(61, SECONDS))), false, "past expiration beyond max skew"),
                    jwtCase(b -> b.expirationTime(Date.from(Instant.now().minus(1, SECONDS))), true, "past expiration within max skew"),
                    jwtCase(b -> b.expirationTime(Date.from(Instant.now().plus(1, MINUTES))), true, "future expiration"),
                    jwtCase(b -> b.claim("foo", "bar"), true, "additional claim")
            );
        }

        @NotNull
        private static Arguments jwtCase(UnaryOperator<JWTClaimsSet.Builder> builderOperator, boolean expectSuccess, String name) {
            return Arguments.of(builderOperator, expectSuccess, name);
        }
    }

}
