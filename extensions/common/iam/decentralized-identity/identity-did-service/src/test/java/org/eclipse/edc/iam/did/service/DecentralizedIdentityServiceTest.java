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
import org.eclipse.edc.iam.did.crypto.key.EcPrivateKeyWrapper;
import org.eclipse.edc.iam.did.crypto.key.KeyPairFactory;
import org.eclipse.edc.iam.did.spi.credentials.CredentialsVerifier;
import org.eclipse.edc.iam.did.spi.document.DidDocument;
import org.eclipse.edc.iam.did.spi.document.EllipticCurvePublicKey;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.iam.did.spi.resolution.DidResolverRegistry;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.monitor.ConsoleMonitor;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.edc.junit.testfixtures.TestUtils.getResourceFileContentAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
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

    private JWK keyPair;
    private final CredentialsVerifier credentialsVerifierMock = mock(CredentialsVerifier.class);
    private final DidResolverRegistry didResolverRegistryMock = mock(DidResolverRegistry.class);
    private DecentralizedIdentityService identityService;

    @BeforeEach
    void setUp() {
        keyPair = getKeyPair();
        var privateKey = new EcPrivateKeyWrapper(keyPair.toECKey());
        var didUrl = "random.did.url";
        identityService = new DecentralizedIdentityService(didResolverRegistryMock, credentialsVerifierMock, new ConsoleMonitor(), privateKey, didUrl, Clock.systemUTC());
    }

    @Test
    void generateAndVerifyJwtToken_valid() {
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.success(Map.of("region", "eu")));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument((ECKey) keyPair.toPublicJWK())));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());
        assertTrue(result.succeeded());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar");
        assertTrue(verificationResult.succeeded());
        assertEquals("eu", verificationResult.getContent().getStringClaim("region"));
    }

    @Test
    void generateAndVerifyJwtToken_wrongPublicKey() {
        var otherKeyPair = getKeyPair();
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.success(Map.of("region", "eu")));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument((ECKey) otherKeyPair.toPublicJWK())));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());

        assertTrue(result.succeeded());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar");
        assertTrue(verificationResult.failed());
        assertThat(verificationResult.getFailureMessages()).contains("Failed to validate token: Token verification failed");
    }

    @Test
    void generateAndVerifyJwtToken_wrongAudience() {
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument((ECKey) keyPair.toPublicJWK())));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar2");
        assertTrue(verificationResult.failed());
    }

    @Test
    void generateAndVerifyJwtToken_getVerifiedCredentialsFailed() {
        var errorMsg = UUID.randomUUID().toString();
        when(credentialsVerifierMock.getVerifiedCredentials(any())).thenReturn(Result.failure(errorMsg));
        when(didResolverRegistryMock.resolve(anyString())).thenReturn(Result.success(createDidDocument((ECKey) keyPair.toPublicJWK())));

        var result = identityService.obtainClientCredentials(defaultTokenParameters());
        assertTrue(result.succeeded());

        var verificationResult = identityService.verifyJwtToken(result.getContent(), "Bar");
        assertTrue(verificationResult.failed());
        assertThat(verificationResult.getFailureDetail()).contains(errorMsg);
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
    private JWK getKeyPair() {
        return KeyPairFactory.generateKeyPairP256();
    }

}
