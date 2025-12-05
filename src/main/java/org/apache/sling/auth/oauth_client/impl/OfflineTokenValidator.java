/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.AbstractTokenValidator;
import org.apache.sling.auth.oauth_client.spi.TokenValidator;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offline token validator that validates JWT tokens using signature verification.
 * This validator parses the JWT, verifies the signature using the JWK Set from the OIDC provider,
 * and validates the issuer and expiration claims.
 */
@Component(service = TokenValidator.class)
@Designate(ocd = OfflineTokenValidator.Config.class, factory = true)
public class OfflineTokenValidator extends AbstractTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(OfflineTokenValidator.class);

    @ObjectClassDefinition(
            name = "Apache Sling OIDC Offline Token Validator",
            description = "Token validator that performs offline JWT signature verification")
    @interface Config {
        @AttributeDefinition(
                name = "Validator Name",
                description =
                        "Unique name for this token validator instance. Used to reference this validator from authentication handlers.")
        String name();

        @AttributeDefinition(
                name = "Accepted Client IDs",
                description =
                        "List of accepted OAuth2 client IDs. Only tokens issued to one of these client IDs will be accepted. If not configured or empty, client ID validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        String[] acceptedClientIds() default {};

        @AttributeDefinition(
                name = "Required Scopes",
                description =
                        "List of required OAuth2 scopes. Tokens must have ALL of these scopes to be accepted. If not configured or empty, scope validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        String[] requiredScopes() default {};

        @AttributeDefinition(
                name = "Required Audiences",
                description =
                        "List of required audiences. Tokens must have at least one of these audiences to be accepted. If not configured or empty, audience validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        String[] requiredAudiences() default {};
    }

    @Activate
    public OfflineTokenValidator(Config config) {
        super(config.name(), config.acceptedClientIds(), config.requiredScopes(), config.requiredAudiences());

        if (config.name() == null || config.name().isEmpty()) {
            throw new IllegalArgumentException("Validator name must be configured");
        }

        // Validate that all configured values are non-empty strings
        validateConfigArray(config.acceptedClientIds(), "Accepted client IDs");
        validateConfigArray(config.requiredScopes(), "Required scopes");
        validateConfigArray(config.requiredAudiences(), "Required audiences");

        logger.info("OfflineTokenValidator '{}' activated", config.name());
    }

    private void validateConfigArray(String[] values, String configName) {
        if (values != null) {
            for (String value : values) {
                if (value == null || value.trim().isEmpty()) {
                    throw new IllegalArgumentException(configName
                            + " configuration contains empty or null values. All entries must be non-empty strings.");
                }
            }
        }
    }

    @Override
    @Nullable
    protected TokenValidationResult doValidate(@NotNull String token, @NotNull ClientConnection connection) {
        try {
            // Parse and validate the token
            JWT jwt = JWTParser.parse(token);
            if (!(jwt instanceof SignedJWT)) {
                logger.debug("Token is not a signed JWT");
                return null;
            }

            SignedJWT signedJWT = (SignedJWT) jwt;
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Resolve the OIDC connection
            ResolvedConnection resolved = ResolvedOidcConnection.resolve(connection);
            if (!(resolved instanceof ResolvedOidcConnection)) {
                logger.debug("Connection is not an OIDC connection");
                return null;
            }

            ResolvedOidcConnection oidcConnection = (ResolvedOidcConnection) resolved;

            // Validate the token signature, issuer, and expiration
            if (!validateTokenSignature(signedJWT, oidcConnection, claimsSet)) {
                return null;
            }

            // Extract subject
            String subject = claimsSet.getSubject();
            if (subject == null || subject.isEmpty()) {
                logger.debug("Token has no subject claim");
                return null;
            }

            logger.debug("Token validated successfully (offline) for subject: {}", subject);
            return new TokenValidationResult(subject, claimsSet);

        } catch (ParseException e) {
            logger.debug("Failed to parse token: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Validates the token signature, issuer, and expiration.
     */
    private boolean validateTokenSignature(
            @NotNull SignedJWT signedJWT, @NotNull ResolvedOidcConnection connection, @NotNull JWTClaimsSet claimsSet) {
        try {
            // Validate issuer
            String issuerClaim = claimsSet.getIssuer();
            if (!connection.issuer().equals(issuerClaim)) {
                logger.debug("Issuer mismatch: expected {}, got {}", connection.issuer(), issuerClaim);
                return false;
            }

            // Validate expiration
            if (claimsSet.getExpirationTime() != null
                    && claimsSet.getExpirationTime().before(new Date())) {
                logger.debug("Token has expired");
                return false;
            }

            // Validate signature using JWK Set
            URL jwkSetURL = connection.jwkSetURL().toURL();
            JWKSet jwkSet = JWKSet.load(jwkSetURL);

            // Get the key ID from the JWT header
            String keyID = signedJWT.getHeader().getKeyID();
            if (keyID == null) {
                logger.debug("No key ID in JWT header");
                return false;
            }

            // Find the matching key in the JWK set
            RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId(keyID);
            if (rsaKey == null) {
                logger.debug("No matching key found for key ID: {}", keyID);
                return false;
            }

            // Verify the signature
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            if (!signedJWT.verify(verifier)) {
                logger.debug("Signature verification failed");
                return false;
            }

            return true;
        } catch (JOSEException | IOException | ParseException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
}
