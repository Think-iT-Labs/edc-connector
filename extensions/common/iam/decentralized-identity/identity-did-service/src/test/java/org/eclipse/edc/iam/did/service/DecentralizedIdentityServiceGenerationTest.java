/*
 *  Copyright (c) 2022 Microsoft Corporation
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.edc.iam.did.crypto.key.EcPrivateKeyWrapper;
import org.eclipse.edc.iam.did.crypto.key.EcPublicKeyWrapper;
import org.eclipse.edc.iam.did.spi.credentials.CredentialsVerifier;
import org.eclipse.edc.iam.did.spi.resolution.DidResolverRegistry;
import org.eclipse.edc.spi.iam.IdentityService;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.monitor.ConsoleMonitor;
import org.eclipse.edc.spi.result.AbstractResult;
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
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static java.time.ZoneOffset.UTC;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.iam.did.crypto.JwtUtils.verify;
import static org.eclipse.edc.iam.did.crypto.key.KeyPairFactory.generateKeyPairP256;
import static org.eclipse.edc.junit.testfixtures.TestUtils.getResourceFileContentAsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DecentralizedIdentityServiceGenerationTest {

    private final Instant now = Instant.now();
    private final Clock clock = Clock.fixed(now, UTC);
    private final CredentialsVerifier credentialsVerifierMock = mock(CredentialsVerifier.class);
    private final DidResolverRegistry didResolverRegistryMock = mock(DidResolverRegistry.class);
    private EcPrivateKeyWrapper privateKey;
    private EcPublicKeyWrapper publicKey;
    private final String issuer = "random.did.url";
    private IdentityService decentralizedIdentityService;

    @BeforeEach
    void setup() throws JOSEException {
        privateKey = new EcPrivateKeyWrapper((ECKey) getJwk("private_p256.pem"));
        publicKey = new EcPublicKeyWrapper((ECKey) getJwk("public_p256.pem"));
        decentralizedIdentityService = new DecentralizedIdentityService(didResolverRegistryMock, credentialsVerifierMock, new ConsoleMonitor(), privateKey, issuer, Clock.systemUTC());
    }

    @Test
    void createVerifiableCredential() {
        var tokenParameters = TokenParameters.Builder.newInstance()
                .audience("test-audience")
                .build();

        var result = decentralizedIdentityService.obtainClientCredentials(tokenParameters);

        assertThat(result).matches(AbstractResult::succeeded)
                .extracting(AbstractResult::getContent)
                .extracting(TokenRepresentation::getToken)
                .extracting(this::parseToJwt)
                .satisfies(jwt -> {
                    assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(issuer);
                    assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(issuer);
                    assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("test-audience");
                    assertThat(jwt.getJWTClaimsSet().getJWTID()).satisfies(UUID::fromString);
                    assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isCloseTo(now.plus(10, MINUTES), 60_000);
                });
    }

    @Test
    void verifyJwt_OnInvalidSignature_fails() {
        var tokenParameters = TokenParameters.Builder.newInstance()
                .audience("test-audience")
                .build();
        var result = decentralizedIdentityService.obtainClientCredentials(tokenParameters);
        var jwt = parseToJwt(result.getContent().getToken());
        var unrelatedPublicKey = new EcPublicKeyWrapper(generateKeyPairP256());

        var verifyResult = verify(jwt, unrelatedPublicKey, "test-audience");

        assertThat(verifyResult.getFailureMessages()).containsExactly("Invalid signature");
    }

    @Test
    void verifyJwt_OnVerificationFailure_fails() throws Exception {
        var jwt = mock(SignedJWT.class);
        var message = "Test Message";
        when(jwt.verify(any())).thenThrow(new JOSEException(message));
        assertThat(verify(jwt, publicKey, "test-audience").getFailureMessages())
                .containsExactly("Unable to verify JWT token. " + message);
    }

    @Test
    void verifyJwt_OnInvalidClaims_fails() throws Exception {
        var jwt = mock(SignedJWT.class);
        var message = "Test Message";
        when(jwt.verify(any())).thenReturn(true);
        when(jwt.getJWTClaimsSet()).thenThrow(new ParseException(message, 0));
        assertThat(verify(jwt, publicKey, "test-audience").getFailureMessages())
                .containsExactly("Error verifying JWT token. The payload must represent a valid JSON object and a JWT claims set. " + message);
    }

    @ParameterizedTest(name = "{2}")
    @ArgumentsSource(ClaimsArgs.class)
    void verifyJwt_OnClaims(UnaryOperator<JWTClaimsSet.Builder> builderOperator, boolean expectSuccess, String ignoredName) throws Exception {
        var tokenParameters = TokenParameters.Builder.newInstance()
                .audience("test-audience")
                .build();
        var result = decentralizedIdentityService.obtainClientCredentials(tokenParameters);
        var vc = parseToJwt(result.getContent().getToken());

        var claimsSetBuilder = new JWTClaimsSet.Builder(vc.getJWTClaimsSet());
        var claimsSet = builderOperator.apply(claimsSetBuilder).build();

        var jwt = new SignedJWT(vc.getHeader(), claimsSet);
        jwt.sign(privateKey.signer());

        var verifyResult = verify(jwt, publicKey, "test-audience");
        assertThat(verifyResult.succeeded()).isEqualTo(expectSuccess);
        if (!expectSuccess) {
            assertThat(verifyResult.getFailureMessages())
                    .isNotEmpty()
                    .allMatch(m -> m.startsWith("Claim verification failed. "));
        }
    }

    @NotNull
    private static Arguments jwtCase(UnaryOperator<JWTClaimsSet.Builder> builderOperator, boolean expectSuccess, String name) {
        return Arguments.of(builderOperator, expectSuccess, name);
    }

    private JWK getJwk(String resourceName) throws JOSEException {
        String privateKeyPem = getResourceFileContentAsString(resourceName);
        return JWK.parseFromPEMEncodedObjects(privateKeyPem);
    }

    static class ClaimsArgs implements ArgumentsProvider {

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
    }

    @NotNull
    private SignedJWT parseToJwt(String it) {
        try {
            return SignedJWT.parse(it);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
