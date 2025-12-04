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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.jackrabbit.oak.spi.security.authentication.credentials.CredentialsSupport;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityProvider;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication handler that validates bearer tokens from the Authorization header.
 * Valid tokens are cached to improve performance.
 */
@Component(service = AuthenticationHandler.class, immediate = true)
@Designate(ocd = OidcBearerAuthenticationHandler.Config.class, factory = true)
public class OidcBearerAuthenticationHandler extends DefaultAuthenticationFeedbackHandler
        implements AuthenticationHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidcBearerAuthenticationHandler.class);
    private static final String AUTH_TYPE = "oidc-bearer";
    private static final String BEARER_PREFIX = "Bearer ";

    private final Map<String, ClientConnection> connections;
    private final Map<String, UserInfoProcessor> userInfoProcessors;
    private final String idp;
    private final String connectionName;
    private final String[] path;
    private final long cacheTtlSeconds;
    private final int cacheMaxSize;
    private final boolean onlineValidation;
    private final boolean fetchUserInfo;
    private final String[] acceptedClientIds;
    private final String[] requiredScopes;
    private final String[] requiredAudiences;

    /**
     * Result of token validation containing the validated claims and connection.
     */
    private static class ValidationResult {
        final String subject;
        final JWTClaimsSet claimsSet;
        final ClientConnection connection;

        ValidationResult(String subject, JWTClaimsSet claimsSet, ClientConnection connection) {
            this.subject = subject;
            this.claimsSet = claimsSet;
            this.connection = connection;
        }
    }

    /**
     * Gets the configured connection.
     *
     * @return the connection to use, or null if not found
     */
    private ClientConnection getConnection() {
        return connections.get(connectionName);
    }

    /**
     * Validates claims (client ID, scopes, audience), caches the token, and creates a ValidationResult.
     *
     * @param token the bearer token
     * @param claimsSet the JWT claims set
     * @param connection the client connection
     * @param validationMode description for logging (e.g., "offline" or "online")
     * @return ValidationResult if valid, null otherwise
     */
    private ValidationResult validateClaimsAndCreateResult(
            @NotNull String token,
            @NotNull JWTClaimsSet claimsSet,
            @NotNull ClientConnection connection,
            @NotNull String validationMode) {

        String subject = claimsSet.getSubject();
        if (subject == null || subject.isEmpty()) {
            logger.debug("Token has no subject claim");
            return null;
        }

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

        // Cache the validated token
        cacheToken(token, subject, claimsSet);

        logger.info("Bearer token validated successfully ({}) for subject: {}", validationMode, subject);

        return new ValidationResult(subject, claimsSet, connection);
    }

    // Cache structure: token -> CachedToken
    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @ObjectClassDefinition(
            name = "Apache Sling OIDC Bearer Authentication Handler",
            description = "Authentication handler for validating OIDC bearer tokens from Authorization header")
    @interface Config {
        @AttributeDefinition(
                name = "Path",
                description =
                        "Repository path for which this authentication handler should be used by Sling. If this is "
                                + "empty, the authentication handler will be disabled. By default this is set to \"/\".")
        String[] path() default {"/"};

        @AttributeDefinition(
                name = "Sync Handler Configuration Name",
                description = "Name of Sync Handler Configuration")
        String idp() default "oidc-bearer";

        @AttributeDefinition(
                name = "Connection Name",
                description =
                        "Name of the OIDC connection to use for bearer token validation. REQUIRED: Must be configured with a valid connection name.")
        String connectionName();

        @AttributeDefinition(
                name = "Online Validation",
                description =
                        "Enable online token validation using OAuth2 token introspection endpoint. When enabled, tokens are validated against the provider's introspection endpoint instead of offline JWT validation. The introspection endpoint is configured on the OIDC connection.")
        boolean onlineValidation() default false;

        @AttributeDefinition(
                name = "Fetch User Info",
                description =
                        "Enable fetching user information from the UserInfo endpoint after token validation. When enabled, the user profile will be synchronized with the identity provider. This requires the token to have the appropriate scope (e.g., 'profile').")
        boolean fetchUserInfo() default false;

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

        @AttributeDefinition(
                name = "Cache TTL (seconds)",
                description =
                        "Time to live for cached tokens in seconds. Default is 300 (5 minutes). Set to 0 to disable caching.")
        long cacheTtlSeconds() default 300;

        @AttributeDefinition(
                name = "Cache Max Size",
                description = "Maximum number of tokens to cache. Default is 1000.")
        int cacheMaxSize() default 1000;

        @AttributeDefinition(name = "Service Ranking", description = "Service ranking for this authentication handler")
        int service_ranking() default 0;
    }

    @Activate
    public OidcBearerAuthenticationHandler(
            @NotNull BundleContext bundleContext,
            @Reference List<ClientConnection> connections,
            @Reference(policyOption = ReferencePolicyOption.GREEDY) List<UserInfoProcessor> userInfoProcessors,
            Config config) {

        this.connections = connections.stream().collect(Collectors.toMap(ClientConnection::name, Function.identity()));
        this.userInfoProcessors = userInfoProcessors.stream()
                .collect(Collectors.toMap(UserInfoProcessor::connection, Function.identity()));
        this.idp = config.idp();
        this.connectionName = config.connectionName();
        this.path = config.path();
        this.cacheTtlSeconds = config.cacheTtlSeconds();
        this.cacheMaxSize = config.cacheMaxSize();
        this.onlineValidation = config.onlineValidation();
        this.fetchUserInfo = config.fetchUserInfo();
        this.acceptedClientIds = config.acceptedClientIds();
        this.requiredScopes = config.requiredScopes();
        this.requiredAudiences = config.requiredAudiences();

        // Validate that connectionName is configured
        if (connectionName == null || connectionName.isEmpty()) {
            throw new IllegalArgumentException("Connection name not configured");
        }

        // Validate that the specified connection exists
        if (!this.connections.containsKey(connectionName)) {
            throw new IllegalArgumentException("Configured connection '" + connectionName
                    + "' not found. Available connections: " + this.connections.keySet());
        }

        // Validate online validation configuration
        if (onlineValidation) {
            logger.debug("Online validation is enabled. Introspection endpoint configured on OIDC connection.");
        }

        // Log fetchUserInfo configuration
        if (fetchUserInfo) {
            logger.debug("User info fetching is enabled. Profile will be synchronized after token validation.");
        }

        // Validate and log accepted client IDs (optional)
        if (acceptedClientIds != null && acceptedClientIds.length > 0) {
            // Check that all client ID entries are non-empty
            for (String clientId : acceptedClientIds) {
                if (clientId == null || clientId.trim().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Accepted client IDs configuration contains empty or null values. All client ID entries must be non-empty strings.");
                }
            }
            logger.debug("Accepted client IDs: {}", String.join(", ", acceptedClientIds));
        } else {
            logger.info("Client ID validation is disabled - no accepted client IDs configured");
        }

        // Validate and log required scopes (optional)
        if (requiredScopes != null && requiredScopes.length > 0) {
            // Check that all scope entries are non-empty
            for (String scope : requiredScopes) {
                if (scope == null || scope.trim().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Required scopes configuration contains empty or null values. All scope entries must be non-empty strings.");
                }
            }
            logger.debug("Required scopes: {}", String.join(", ", requiredScopes));
        } else {
            logger.info("Scope validation is disabled - no required scopes configured");
        }

        // Validate and log required audiences (optional)
        if (requiredAudiences != null && requiredAudiences.length > 0) {
            // Check that all audience entries are non-empty
            for (String audience : requiredAudiences) {
                if (audience == null || audience.trim().isEmpty()) {
                    throw new IllegalArgumentException(
                            "Required audiences configuration contains empty or null values. All audience entries must be non-empty strings.");
                }
            }
            logger.debug("Required audiences: {}", String.join(", ", requiredAudiences));
        } else {
            logger.info("Audience validation is disabled - no required audiences configured");
        }

        // Log cache configuration
        if (cacheTtlSeconds <= 0) {
            logger.info("Token caching is disabled - cache TTL is 0 or negative");
        }

        logger.debug("activate: registering ExternalIdentityProvider");
        bundleContext.registerService(
                new String[] {ExternalIdentityProvider.class.getName(), CredentialsSupport.class.getName()},
                new OidcIdentityProvider(idp),
                null);

        logger.info(
                "OidcBearerAuthenticationHandler successfully activated with connection: {}, validation: {}, cache TTL: {}s, max size: {}",
                connectionName,
                onlineValidation ? "online" : "offline",
                cacheTtlSeconds,
                cacheMaxSize);
    }

    @Override
    public AuthenticationInfo extractCredentials(
            @NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        logger.debug("extractCredentials: checking for bearer token");

        // Extract the Authorization header
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            logger.debug("No bearer token found in Authorization header");
            return null;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            logger.debug("Empty bearer token");
            return null;
        }

        try {
            // Check cache first (only if caching is enabled)
            if (cacheTtlSeconds > 0) {
                CachedToken cachedToken = tokenCache.get(token);
                if (cachedToken != null && !cachedToken.isExpired()) {
                    logger.debug("Using cached token for subject: {}", cachedToken.subject);
                    return createAuthenticationInfo(cachedToken.subject, cachedToken.claimsSet, token);
                }
            }

            // Choose validation method
            ValidationResult validationResult;
            if (onlineValidation) {
                validationResult = validateTokenOnline(token);
            } else {
                validationResult = validateTokenOffline(token);
            }

            if (validationResult == null) {
                return null;
            }

            // Fetch user info if enabled
            String userInfoJson = null;
            if (fetchUserInfo && validationResult.connection != null) {
                userInfoJson = fetchUserInfoJson(token, validationResult.connection);
            }

            return createAuthenticationInfoWithProcessor(
                    validationResult.subject,
                    validationResult.connection,
                    userInfoJson,
                    validationResult.claimsSet.getClaims(),
                    token);

        } catch (ParseException e) {
            logger.debug("Failed to parse bearer token: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("Error validating bearer token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Validates the token offline using JWT signature verification.
     *
     * @param token the bearer token
     * @return ValidationResult if valid, null otherwise
     */
    private ValidationResult validateTokenOffline(@NotNull String token) throws ParseException {
        // Parse and validate the token
        JWT jwt = JWTParser.parse(token);
        if (!(jwt instanceof SignedJWT)) {
            logger.debug("Token is not a signed JWT");
            return null;
        }

        SignedJWT signedJWT = (SignedJWT) jwt;
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        // Get the configured connection
        ClientConnection connection = getConnection();
        if (connection == null) {
            logger.debug("Configured connection '{}' not found", connectionName);
            return null;
        }

        // Validate the token against the connection
        ClientConnection validClientConnection = null;
        try {
            ResolvedConnection resolved = ResolvedOidcConnection.resolve(connection);
            if (resolved instanceof ResolvedOidcConnection) {
                ResolvedOidcConnection resolvedConnection = (ResolvedOidcConnection) resolved;
                if (validateToken(signedJWT, resolvedConnection, claimsSet)) {
                    validClientConnection = connection;
                }
            }
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
        }

        if (validClientConnection == null) {
            logger.debug("Token validation failed");
            return null;
        }

        return validateClaimsAndCreateResult(token, claimsSet, validClientConnection, "offline");
    }

    /**
     * Validates the token online using OAuth2 token introspection.
     *
     * @param token the bearer token
     * @return ValidationResult if valid, null otherwise
     */
    private ValidationResult validateTokenOnline(@NotNull String token) {
        try {
            // Get the configured connection
            ClientConnection connection = getConnection();
            if (connection == null) {
                return null;
            }

            // Get introspection endpoint from connection
            String endpoint = null;
            if (connection instanceof OidcConnectionImpl) {
                OidcConnectionImpl oidcConn = (OidcConnectionImpl) connection;
                java.net.URI introspectionUri = oidcConn.introspectionEndpoint();
                if (introspectionUri != null) {
                    endpoint = introspectionUri.toString();
                    logger.debug("Using introspection endpoint: {}", endpoint);
                }
            }

            if (endpoint == null || endpoint.isEmpty()) {
                logger.debug(
                        "No introspection endpoint available. Configure on OIDC connection or ensure connection uses baseUrl for auto-discovery.");
                return null;
            }

            // Get client credentials for introspection
            ResolvedConnection resolved = ResolvedOidcConnection.resolve(connection);
            if (!(resolved instanceof ResolvedOidcConnection)) {
                logger.debug("Connection is not an OIDC connection");
                return null;
            }

            ResolvedOidcConnection oidcConnection = (ResolvedOidcConnection) resolved;
            String clientId = oidcConnection.clientId();
            String clientSecret = oidcConnection.clientSecret();

            if (clientId == null || clientSecret == null) {
                logger.debug("Client credentials not available for introspection");
                return null;
            }

            // Perform token introspection
            ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
            AccessToken accessToken = new BearerAccessToken(token);
            TokenIntrospectionRequest introspectionRequest =
                    new TokenIntrospectionRequest(new java.net.URI(endpoint), clientAuth, accessToken);

            HTTPResponse httpResponse = introspectionRequest.toHTTPRequest().send();
            TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse.parse(httpResponse);

            if (!introspectionResponse.indicatesSuccess()) {
                logger.debug("Token introspection failed");
                return null;
            }

            com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse successResponse =
                    introspectionResponse.toSuccessResponse();

            if (!successResponse.isActive()) {
                logger.debug("Token is not active");
                return null;
            }

            // Extract claims from introspection response
            String subject = successResponse.getSubject() != null
                    ? successResponse.getSubject().getValue()
                    : null;
            if (subject == null || subject.isEmpty()) {
                logger.debug("Token has no subject claim");
                return null;
            }

            // Create a JWTClaimsSet from introspection response for consistency
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().subject(subject);

            if (successResponse.getIssuer() != null) {
                claimsBuilder.issuer(successResponse.getIssuer().getValue());
            }
            if (successResponse.getExpirationTime() != null) {
                claimsBuilder.expirationTime(successResponse.getExpirationTime());
            }
            if (successResponse.getIssueTime() != null) {
                claimsBuilder.issueTime(successResponse.getIssueTime());
            }
            if (successResponse.getAudience() != null
                    && !successResponse.getAudience().isEmpty()) {
                claimsBuilder.audience(successResponse.getAudience().stream()
                        .map(aud -> aud.getValue())
                        .collect(Collectors.toList()));
            }
            if (successResponse.getUsername() != null) {
                claimsBuilder.claim("username", successResponse.getUsername());
            }
            if (successResponse.getScope() != null) {
                claimsBuilder.claim("scope", successResponse.getScope().toString());
            }
            // Extract client_id from the JSON object
            try {
                net.minidev.json.JSONObject jsonObject = successResponse.toJSONObject();
                if (jsonObject.containsKey("client_id")) {
                    claimsBuilder.claim("client_id", jsonObject.get("client_id").toString());
                }
            } catch (Exception e) {
                logger.debug("Failed to extract client_id from introspection response: {}", e.getMessage());
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            return validateClaimsAndCreateResult(token, claimsSet, connection, "online");

        } catch (Exception e) {
            logger.debug("Online token validation failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Validates that the token's client ID is in the list of accepted client IDs.
     *
     * @param claimsSet the JWT claims set
     * @return true if client ID validation passes or is not configured, false otherwise
     */
    private boolean validateClientId(@NotNull JWTClaimsSet claimsSet) {
        if (acceptedClientIds == null || acceptedClientIds.length == 0) {
            // No client ID validation configured - skip validation
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
    private boolean validateScopes(@NotNull JWTClaimsSet claimsSet) {
        if (requiredScopes == null || requiredScopes.length == 0) {
            // No scope validation configured - skip validation
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
    private boolean validateAudience(@NotNull JWTClaimsSet claimsSet) {
        if (requiredAudiences == null || requiredAudiences.length == 0) {
            // No audience validation configured - skip validation
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
     * Validates the token using the OIDC connection configuration.
     *
     * @param signedJWT the signed JWT to validate
     * @param connection the OIDC connection to use for validation
     * @param claimsSet the JWT claims set
     * @return true if the token is valid, false otherwise
     */
    private boolean validateToken(
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
                    && claimsSet.getExpirationTime().before(new java.util.Date())) {
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
        } catch (JOSEException | java.io.IOException | ParseException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Fetches user information from the UserInfo endpoint and returns it as JSON string.
     *
     * @param token the bearer token to use for authentication
     * @param connection the OIDC connection
     * @return user info as JSON string, or null if fetch fails
     */
    private String fetchUserInfoJson(@NotNull String token, @NotNull ClientConnection connection) {
        try {
            // Get userInfo URL from connection
            String userInfoUrl = null;
            if (connection instanceof OidcConnectionImpl) {
                OidcConnectionImpl oidcConn = (OidcConnectionImpl) connection;
                userInfoUrl = oidcConn.userInfoUrl();
            }

            if (userInfoUrl == null || userInfoUrl.isEmpty()) {
                logger.debug("No userInfo URL available for connection: {}", connection.name());
                return null;
            }

            logger.debug("Fetching user info from: {}", userInfoUrl);

            // Make HTTP request to UserInfo endpoint
            java.net.HttpURLConnection urlConnection =
                    (java.net.HttpURLConnection) new URL(userInfoUrl).openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.setRequestProperty("Authorization", "Bearer " + token);
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setConnectTimeout(5000);
            urlConnection.setReadTimeout(5000);

            int responseCode = urlConnection.getResponseCode();
            if (responseCode != 200) {
                logger.debug("UserInfo request failed with status: {}", responseCode);
                return null;
            }

            // Parse the UserInfo response
            String responseBody =
                    new String(urlConnection.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            com.nimbusds.oauth2.sdk.http.HTTPResponse httpResponse = new HTTPResponse(responseCode);
            httpResponse.setContentType("application/json");
            httpResponse.setContent(responseBody);

            com.nimbusds.openid.connect.sdk.UserInfoResponse userInfoResponse =
                    com.nimbusds.openid.connect.sdk.UserInfoResponse.parse(httpResponse);

            if (!userInfoResponse.indicatesSuccess()) {
                logger.debug("UserInfo response indicates failure");
                return null;
            }

            com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse successResponse =
                    userInfoResponse.toSuccessResponse();
            com.nimbusds.openid.connect.sdk.claims.UserInfo userInfo = successResponse.getUserInfo();

            if (userInfo == null) {
                logger.debug("UserInfo response is empty");
                return null;
            }

            String userInfoJson = userInfo.toJSONObject().toJSONString();
            logger.debug("Successfully fetched user info for connection: {}", connection.name());
            return userInfoJson;

        } catch (Exception e) {
            logger.debug("Failed to fetch user info: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Creates an AuthenticationInfo object using the UserInfoProcessor.
     *
     * @param subject the subject from the token
     * @param connection the OIDC connection used for validation
     * @param userInfoJson the user info JSON (may be null)
     * @param tokenClaims the token claims as a map
     * @param token the raw token string
     * @return AuthenticationInfo object
     */
    private @NotNull AuthenticationInfo createAuthenticationInfoWithProcessor(
            @NotNull String subject,
            @NotNull ClientConnection connection,
            String userInfoJson,
            @NotNull Map<String, Object> tokenClaims,
            @NotNull String token) {

        // Get the UserInfoProcessor for this connection
        UserInfoProcessor processor = userInfoProcessors.get(connection.name());
        if (processor == null) {
            logger.warn(
                    "No UserInfoProcessor found for connection '{}'. Using fallback credentials creation.",
                    connection.name());
            // Fallback to manual creation if no processor is available
            return createAuthenticationInfoFallback(subject, tokenClaims, token);
        }

        // Create a token response JSON from the claims
        // The UserInfoProcessor expects a token response format
        net.minidev.json.JSONObject tokenResponseJson = new net.minidev.json.JSONObject();
        tokenResponseJson.put("access_token", token);
        tokenResponseJson.put("token_type", "Bearer");
        // Add token claims to the response
        for (Map.Entry<String, Object> entry : tokenClaims.entrySet()) {
            tokenResponseJson.put(entry.getKey(), entry.getValue());
        }

        String tokenResponseString = tokenResponseJson.toJSONString();

        // Process using the UserInfoProcessor
        OidcAuthCredentials credentials = processor.process(userInfoJson, tokenResponseString, subject, idp);

        // Create AuthenticationInfo
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Fallback method to create AuthenticationInfo when no UserInfoProcessor is available.
     *
     * @param subject the subject from the token
     * @param tokenClaims the token claims
     * @param token the raw token string
     * @return AuthenticationInfo object
     */
    private @NotNull AuthenticationInfo createAuthenticationInfoFallback(
            @NotNull String subject, @NotNull Map<String, Object> tokenClaims, @NotNull String token) {
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);

        // Create credentials with claims
        OidcAuthCredentials credentials = new OidcAuthCredentials(subject, idp);
        credentials.setAttribute(".token", token);

        // Add all claims as attributes (converting Object values to String)
        for (Map.Entry<String, Object> entry : tokenClaims.entrySet()) {
            if (entry.getValue() != null) {
                credentials.setAttribute(entry.getKey(), entry.getValue().toString());
            }
        }

        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Creates an AuthenticationInfo object from the validated token.
     *
     * @param subject the subject from the token
     * @param claimsSet the JWT claims set
     * @param token the raw token string
     * @return the AuthenticationInfo object
     */
    private @NotNull AuthenticationInfo createAuthenticationInfo(
            @NotNull String subject, @NotNull JWTClaimsSet claimsSet, @NotNull String token) {
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);

        // Create credentials with claims
        OidcAuthCredentials credentials = new OidcAuthCredentials(subject, idp);
        credentials.setAttribute(".token", token);

        // Add all claims as attributes (converting Object values to String)
        for (Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet()) {
            if (entry.getValue() != null) {
                credentials.setAttribute(entry.getKey(), entry.getValue().toString());
            }
        }

        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Caches a validated token.
     *
     * @param token the token string
     * @param subject the subject from the token
     * @param claimsSet the JWT claims set
     */
    private void cacheToken(@NotNull String token, @NotNull String subject, @NotNull JWTClaimsSet claimsSet) {
        // Skip caching if disabled
        if (cacheTtlSeconds <= 0) {
            logger.debug("Token caching is disabled - not caching token for subject: {}", subject);
            return;
        }

        // Enforce cache size limit
        if (tokenCache.size() >= cacheMaxSize) {
            // Remove oldest entries (simple LRU-like behavior)
            long now = System.currentTimeMillis();
            tokenCache
                    .entrySet()
                    .removeIf(entry -> entry.getValue().isExpired()
                            || now - entry.getValue().cachedAt > TimeUnit.SECONDS.toMillis(cacheTtlSeconds));

            // If still over limit, remove oldest entries
            if (tokenCache.size() >= cacheMaxSize) {
                tokenCache.entrySet().stream()
                        .sorted((e1, e2) -> Long.compare(e1.getValue().cachedAt, e2.getValue().cachedAt))
                        .limit(tokenCache.size() - cacheMaxSize + 1)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toList())
                        .forEach(tokenCache::remove);
            }
        }

        tokenCache.put(token, new CachedToken(subject, claimsSet, cacheTtlSeconds));
        logger.debug("Cached token for subject: {} (cache size: {})", subject, tokenCache.size());
    }

    /**
     * Clears the token cache.
     */
    public void clearCache() {
        tokenCache.clear();
        logger.info("Token cache cleared");
    }

    /**
     * Gets the current cache size.
     *
     * @return the number of tokens in the cache
     */
    public int getCacheSize() {
        return tokenCache.size();
    }

    @Override
    public boolean requestCredentials(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response)
            throws IOException {
        logger.debug("requestCredentials: bearer authentication handler does not request credentials");
        // Bearer token authentication handler does not request credentials
        // Client must provide bearer token in Authorization header
        return false;
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) {
        // For bearer tokens, we don't need to do anything special on logout
        // The client should discard the token
        logger.debug("dropCredentials called");
    }

    /**
     * Internal class to represent a cached token with expiration.
     */
    private static class CachedToken {
        final String subject;
        final JWTClaimsSet claimsSet;
        final long cachedAt;
        final long ttlMillis;

        CachedToken(String subject, JWTClaimsSet claimsSet, long ttlSeconds) {
            this.subject = subject;
            this.claimsSet = claimsSet;
            this.cachedAt = System.currentTimeMillis();
            this.ttlMillis = TimeUnit.SECONDS.toMillis(ttlSeconds);
        }

        boolean isExpired() {
            return System.currentTimeMillis() - cachedAt > ttlMillis;
        }
    }
}
