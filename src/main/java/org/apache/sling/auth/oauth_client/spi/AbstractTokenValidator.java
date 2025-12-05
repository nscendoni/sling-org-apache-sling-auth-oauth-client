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
package org.apache.sling.auth.oauth_client.spi;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jwt.JWTClaimsSet;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for token validators that provides common claims validation logic.
 * Implementations should extend this class and implement the {@link #doValidate(String, org.apache.sling.auth.oauth_client.ClientConnection)}
 * method to perform the actual token validation (e.g., offline JWT signature verification or online introspection).
 */
public abstract class AbstractTokenValidator implements TokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(AbstractTokenValidator.class);

    private final String name;
    private final String[] acceptedClientIds;
    private final String[] requiredScopes;
    private final String[] requiredAudiences;

    /**
     * Constructor for the abstract token validator.
     *
     * @param name the unique name of this validator instance
     * @param acceptedClientIds list of accepted client IDs (null or empty to skip validation)
     * @param requiredScopes list of required scopes (null or empty to skip validation)
     * @param requiredAudiences list of required audiences (null or empty to skip validation)
     */
    protected AbstractTokenValidator(
            @NotNull String name,
            @Nullable String[] acceptedClientIds,
            @Nullable String[] requiredScopes,
            @Nullable String[] requiredAudiences) {
        this.name = name;
        this.acceptedClientIds = acceptedClientIds;
        this.requiredScopes = requiredScopes;
        this.requiredAudiences = requiredAudiences;

        // Log configuration
        if (acceptedClientIds != null && acceptedClientIds.length > 0) {
            logger.debug("Validator '{}' - Accepted client IDs: {}", name, String.join(", ", acceptedClientIds));
        } else {
            logger.info("Validator '{}' - Client ID validation is disabled", name);
        }

        if (requiredScopes != null && requiredScopes.length > 0) {
            logger.debug("Validator '{}' - Required scopes: {}", name, String.join(", ", requiredScopes));
        } else {
            logger.info("Validator '{}' - Scope validation is disabled", name);
        }

        if (requiredAudiences != null && requiredAudiences.length > 0) {
            logger.debug("Validator '{}' - Required audiences: {}", name, String.join(", ", requiredAudiences));
        } else {
            logger.info("Validator '{}' - Audience validation is disabled", name);
        }
    }

    @Override
    @NotNull
    public final String name() {
        return name;
    }

    @Override
    @Nullable
    public final TokenValidationResult validate(
            @NotNull String token, @NotNull org.apache.sling.auth.oauth_client.ClientConnection connection) {
        // First, perform the implementation-specific validation (signature or introspection)
        TokenValidationResult result = doValidate(token, connection);
        if (result == null) {
            return null;
        }

        // Then validate claims
        JWTClaimsSet claimsSet = result.getClaimsSet();

        // Validate client ID
        if (!validateClientId(claimsSet)) {
            return null;
        }

        // Validate scopes
        if (!validateScopes(claimsSet)) {
            return null;
        }

        // Validate audience
        if (!validateAudience(claimsSet)) {
            return null;
        }

        return result;
    }

    /**
     * Performs the implementation-specific token validation.
     * Subclasses must implement this method to perform the actual token validation
     * (e.g., JWT signature verification for offline validation, or introspection for online validation).
     *
     * @param token the bearer token to validate
     * @param connection the OIDC connection to use for validation
     * @return a TokenValidationResult if the token is valid (before claims validation), null otherwise
     */
    @Nullable
    protected abstract TokenValidationResult doValidate(
            @NotNull String token, @NotNull org.apache.sling.auth.oauth_client.ClientConnection connection);

    /**
     * Validates that the token's client ID is in the list of accepted client IDs.
     *
     * @param claimsSet the JWT claims set
     * @return true if client ID validation passes or is not configured, false otherwise
     */
    protected boolean validateClientId(@NotNull JWTClaimsSet claimsSet) {
        if (acceptedClientIds == null || acceptedClientIds.length == 0) {
            logger.debug("No accepted client IDs configured - skipping client ID validation");
            return true;
        }

        // Get client_id claim from the token (try both client_id and azp)
        String clientId = null;
        try {
            clientId = claimsSet.getStringClaim("client_id");
            if (clientId == null || clientId.isEmpty()) {
                // Try azp (authorized party) as fallback - commonly used in Keycloak
                clientId = claimsSet.getStringClaim("azp");
            }
        } catch (ParseException e) {
            logger.debug("Failed to parse client_id from token: {}", e.getMessage());
        }

        if (clientId == null || clientId.isEmpty()) {
            logger.debug("Token does not contain a client_id or azp claim");
            return false;
        }

        // Check if client_id is in the accepted list
        for (String acceptedClientId : acceptedClientIds) {
            if (clientId.equals(acceptedClientId)) {
                logger.debug("Token client_id '{}' is accepted", clientId);
                return true;
            }
        }

        logger.debug(
                "Token client_id '{}' is not in the list of accepted client IDs: {}",
                clientId,
                String.join(", ", acceptedClientIds));
        return false;
    }

    /**
     * Validates that the token has ALL of the required scopes.
     *
     * @param claimsSet the JWT claims set
     * @return true if scope validation passes or is not configured, false otherwise
     */
    protected boolean validateScopes(@NotNull JWTClaimsSet claimsSet) {
        if (requiredScopes == null || requiredScopes.length == 0) {
            logger.debug("No required scopes configured - skipping scope validation");
            return true;
        }

        // Try to get scopes from the token
        String scopeString = null;
        try {
            scopeString = claimsSet.getStringClaim("scope");
            if (scopeString == null) {
                scopeString = claimsSet.getStringClaim("scp");
            }
        } catch (ParseException e) {
            logger.debug("Failed to parse scope from token: {}", e.getMessage());
        }

        if (scopeString == null || scopeString.isEmpty()) {
            logger.debug("Token does not contain a scope claim");
            return false;
        }

        // Split scopes (usually space-separated)
        List<String> tokenScopesList = Arrays.asList(scopeString.split("\\s+"));

        // Check if token has ALL required scopes
        for (String requiredScope : requiredScopes) {
            if (!tokenScopesList.contains(requiredScope)) {
                logger.debug(
                        "Token is missing required scope '{}'. Token scopes: {}, Required scopes: {}",
                        requiredScope,
                        scopeString,
                        String.join(", ", requiredScopes));
                return false;
            }
        }

        logger.debug("Token has all required scopes: {}", String.join(", ", requiredScopes));
        return true;
    }

    /**
     * Validates that the token's audience matches one of the accepted audiences.
     *
     * @param claimsSet the JWT claims set
     * @return true if audience validation passes or is not configured, false otherwise
     */
    protected boolean validateAudience(@NotNull JWTClaimsSet claimsSet) {
        if (requiredAudiences == null || requiredAudiences.length == 0) {
            logger.debug("No required audiences configured - skipping audience validation");
            return true;
        }

        List<String> tokenAudiences = claimsSet.getAudience();
        if (tokenAudiences == null || tokenAudiences.isEmpty()) {
            logger.debug("Token does not contain an audience claim");
            return false;
        }

        // Check if token has at least one of the required audiences
        for (String tokenAudience : tokenAudiences) {
            for (String requiredAudience : requiredAudiences) {
                if (tokenAudience.equals(requiredAudience)) {
                    logger.debug("Token has required audience: {}", tokenAudience);
                    return true;
                }
            }
        }

        logger.debug("Token does not have any of the required audiences: {}", Arrays.toString(requiredAudiences));
        return false;
    }

    /**
     * Gets the accepted client IDs configuration.
     *
     * @return the accepted client IDs array, or null if not configured
     */
    @Nullable
    protected String[] getAcceptedClientIds() {
        return acceptedClientIds;
    }

    /**
     * Gets the required scopes configuration.
     *
     * @return the required scopes array, or null if not configured
     */
    @Nullable
    protected String[] getRequiredScopes() {
        return requiredScopes;
    }

    /**
     * Gets the required audiences configuration.
     *
     * @return the required audiences array, or null if not configured
     */
    @Nullable
    protected String[] getRequiredAudiences() {
        return requiredAudiences;
    }
}
