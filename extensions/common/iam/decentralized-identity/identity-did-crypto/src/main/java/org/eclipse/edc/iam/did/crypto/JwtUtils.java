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

package org.eclipse.edc.iam.did.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import org.eclipse.edc.iam.did.spi.key.PublicKeyWrapper;
import org.eclipse.edc.spi.result.Result;

import java.text.ParseException;
import java.util.Set;

import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.EXPIRATION_TIME;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.ISSUER;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.SUBJECT;

/**
 * Convenience/helper class to generate and verify Signed JSON Web Tokens (JWTs) for communicating between connector instances.
 */
public class JwtUtils {

    /**
     * Verifies a VerifiableCredential using the issuer's public key
     *
     * @param jwt       a {@link SignedJWT} that was sent by the claiming party.
     * @param publicKey The claiming party's public key, passed as a {@link PublicKeyWrapper}
     * @param audience  The intended audience
     * @return true if verified, false otherwise
     */
    public static Result<Void> verify(SignedJWT jwt, PublicKeyWrapper publicKey, String audience) {
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
