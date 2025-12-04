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
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.apache.sling.testing.mock.osgi.junit5.OsgiContext;
import org.apache.sling.testing.mock.osgi.junit5.OsgiContextExtension;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.osgi.framework.BundleContext;
import org.osgi.util.converter.Converters;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(OsgiContextExtension.class)
class OidcBearerAuthenticationHandlerTest {

    private static final String ISSUER = "https://test-issuer.example.com";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SUBJECT = "test-subject";

    private OsgiContext osgiContext = new OsgiContext();
    private BundleContext bundleContext;
    private List<ClientConnection> connections;
    private List<UserInfoProcessor> userInfoProcessors;
    private OidcBearerAuthenticationHandler handler;
    private OidcBearerAuthenticationHandler.Config config;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpServer jwkServer;
    private RSAKey rsaKey;
    private JWSSigner signer;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RSA key pair for signing tokens
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key-id").generate();
        signer = new RSASSASigner(rsaKey);

        // Start JWK endpoint server
        jwkServer = createJwkServer();

        // Create mock request and response
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);

        // Create mock connection using explicit endpoints (not baseUrl)
        OidcConnectionImpl connection = createMockConnection("test-connection");

        connections = new ArrayList<>();
        connections.add(connection);

        // Create mock UserInfoProcessor
        UserInfoProcessor processor = createMockUserInfoProcessor("test-connection");
        userInfoProcessors = new ArrayList<>();
        userInfoProcessors.add(processor);

        // Create configuration
        config = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        bundleContext = osgiContext.bundleContext();

        // Create handler
        handler = new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, config);
    }

    private UserInfoProcessor createMockUserInfoProcessor(String connectionName) {
        return new UserInfoProcessor() {
            @Override
            public @NotNull OidcAuthCredentials process(
                    String userInfo, @NotNull String tokenResponse, @NotNull String oidcSubject, @NotNull String idp) {
                // Simple processor that creates credentials from token response
                OidcAuthCredentials credentials = new OidcAuthCredentials(oidcSubject, idp);
                credentials.setAttribute(".token", tokenResponse);

                // Parse tokenResponse to extract claims
                try {
                    net.minidev.json.JSONObject tokenJson =
                            (net.minidev.json.JSONObject) net.minidev.json.JSONValue.parse(tokenResponse);
                    for (Map.Entry<String, Object> entry : tokenJson.entrySet()) {
                        if (entry.getValue() != null && !entry.getKey().equals("access_token")) {
                            credentials.setAttribute(
                                    entry.getKey(), entry.getValue().toString());
                        }
                    }
                } catch (Exception e) {
                    // Ignore parsing errors
                }

                // Parse userInfo if available and add attributes (can override token claims)
                if (userInfo != null && !userInfo.isEmpty()) {
                    try {
                        net.minidev.json.JSONObject userInfoJson =
                                (net.minidev.json.JSONObject) net.minidev.json.JSONValue.parse(userInfo);
                        for (Map.Entry<String, Object> entry : userInfoJson.entrySet()) {
                            if (entry.getValue() != null) {
                                credentials.setAttribute(
                                        entry.getKey(), entry.getValue().toString());
                            }
                        }
                    } catch (Exception e) {
                        // Ignore parsing errors
                    }
                }

                return credentials;
            }

            @Override
            public @NotNull String connection() {
                return connectionName;
            }
        };
    }

    private OidcConnectionImpl createMockConnection(String name) {
        return new OidcConnectionImpl(
                Converters.standardConverter()
                        .convert(new java.util.HashMap<String, Object>() {
                            {
                                put("name", name);
                                put("baseUrl", "");
                                put("authorizationEndpoint", "http://localhost/auth");
                                put("tokenEndpoint", "http://localhost/token");
                                put("userInfoUrl", "http://localhost/userinfo");
                                put(
                                        "jwkSetURL",
                                        "http://localhost:"
                                                + jwkServer.getAddress().getPort() + "/.well-known/jwks.json");
                                put("issuer", ISSUER);
                                put("introspectionEndpoint", "");
                                put("clientId", CLIENT_ID);
                                put("clientSecret", "secret");
                                put("scopes", new String[] {"openid"});
                                put("additionalAuthorizationParameters", new String[0]);
                            }
                        })
                        .to(OidcConnectionImpl.Config.class),
                null);
    }

    @AfterEach
    void tearDown() {
        if (jwkServer != null) {
            jwkServer.stop(0);
        }
    }

    @Test
    void testExtractCredentials_NoAuthorizationHeader() {
        when(request.getHeader("Authorization")).thenReturn(null);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null when no Authorization header is present");
    }

    @Test
    void testExtractCredentials_NotBearerToken() {
        when(request.getHeader("Authorization")).thenReturn("Basic dGVzdDp0ZXN0");

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null when Authorization header is not Bearer type");
    }

    @Test
    void testExtractCredentials_EmptyBearerToken() {
        when(request.getHeader("Authorization")).thenReturn("Bearer ");

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null when bearer token is empty");
    }

    @Test
    void testExtractCredentials_ValidToken() throws Exception {
        String token = createValidToken();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNotNull(authInfo, "Should return AuthenticationInfo for valid token");
        assertEquals("oidc-bearer", authInfo.getAuthType());
        assertEquals(SUBJECT, authInfo.getUser());

        Object credentials = authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
        assertNotNull(credentials);
        assertTrue(credentials instanceof OidcAuthCredentials);

        OidcAuthCredentials oidcCreds = (OidcAuthCredentials) credentials;
        assertEquals(SUBJECT, oidcCreds.getUserId());
        assertNotNull(oidcCreds.getAttribute(".token"));
    }

    @Test
    void testExtractCredentials_ExpiredToken() throws Exception {
        // Create token that expired 1 hour ago
        Date expiration = new Date(System.currentTimeMillis() - 3600000);
        String token = createToken(SUBJECT, expiration);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null for expired token");
    }

    @Test
    void testExtractCredentials_InvalidIssuer() throws Exception {
        String token = createTokenWithIssuer("https://wrong-issuer.example.com");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null for token with invalid issuer");
    }

    @Test
    void testExtractCredentials_MalformedToken() {
        when(request.getHeader("Authorization")).thenReturn("Bearer not.a.valid.jwt.token");

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null for malformed token");
    }

    @Test
    void testExtractCredentials_CachingWorks() throws Exception {
        String token = createValidToken();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        // First call - should validate and cache
        AuthenticationInfo authInfo1 = handler.extractCredentials(request, response);
        assertNotNull(authInfo1);
        assertEquals(1, handler.getCacheSize());

        // Second call - should use cache
        AuthenticationInfo authInfo2 = handler.extractCredentials(request, response);
        assertNotNull(authInfo2);
        assertEquals(1, handler.getCacheSize());

        // Verify both return the same user
        assertEquals(authInfo1.getUser(), authInfo2.getUser());
    }

    @Test
    void testExtractCredentials_CacheExpiration() throws Exception {
        // Create handler with very short cache TTL
        OidcBearerAuthenticationHandler.Config shortTtlConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 1L); // 1 second TTL
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler shortTtlHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, shortTtlConfig);

        String token = createValidToken();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        // First call
        AuthenticationInfo authInfo1 = shortTtlHandler.extractCredentials(request, response);
        assertNotNull(authInfo1);

        // Wait for cache to expire
        Thread.sleep(1100);

        // Second call - cache should be expired
        AuthenticationInfo authInfo2 = shortTtlHandler.extractCredentials(request, response);
        assertNotNull(authInfo2);
    }

    @Test
    void testExtractCredentials_CacheMaxSize() throws Exception {
        // Create handler with small cache
        OidcBearerAuthenticationHandler.Config smallCacheConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 2);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler smallCacheHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, smallCacheConfig);

        // Add 3 tokens - cache should evict oldest
        for (int i = 1; i <= 3; i++) {
            String token = createToken("user" + i, new Date(System.currentTimeMillis() + 3600000));
            when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
            smallCacheHandler.extractCredentials(request, response);
        }

        // Cache size should not exceed max
        assertTrue(smallCacheHandler.getCacheSize() <= 2);
    }

    @Test
    void testClearCache() throws Exception {
        String token = createValidToken();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        handler.extractCredentials(request, response);
        assertEquals(1, handler.getCacheSize());

        handler.clearCache();
        assertEquals(0, handler.getCacheSize());
    }

    @Test
    void testRequestCredentials() throws IOException {
        boolean result = handler.requestCredentials(request, response);

        assertFalse(result, "Should return false - bearer authentication handler does not request credentials");
        // Bearer authentication handler does not send any response
        verify(response, never()).setHeader(anyString(), anyString());
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void testDropCredentials() {
        // Should not throw exception
        assertDoesNotThrow(() -> handler.dropCredentials(request, response));
    }

    @Test
    void testExtractCredentials_OnlineValidation() throws Exception {
        // Create a mock introspection endpoint
        HttpServer introspectionServer = HttpServer.create(new InetSocketAddress(0), 0);
        introspectionServer.createContext("/introspect", exchange -> {
            // Return successful introspection response
            String responseJson = "{"
                    + "\"active\": true,"
                    + "\"sub\": \"" + SUBJECT + "\","
                    + "\"iss\": \"" + ISSUER + "\","
                    + "\"client_id\": \"" + CLIENT_ID + "\","
                    + "\"username\": \"test-user\","
                    + "\"scope\": \"openid\","
                    + "\"aud\": \"test-audience\","
                    + "\"exp\": " + (System.currentTimeMillis() / 1000 + 3600) + ","
                    + "\"iat\": " + (System.currentTimeMillis() / 1000) + ""
                    + "}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, responseJson.getBytes().length);
            exchange.getResponseBody().write(responseJson.getBytes());
            exchange.getResponseBody().close();
        });
        introspectionServer.start();

        try {
            // Create connection with introspection endpoint
            OidcConnectionImpl connectionWithIntrospection = new OidcConnectionImpl(
                    Converters.standardConverter()
                            .convert(new java.util.HashMap<String, Object>() {
                                {
                                    put("name", "test-connection-introspection");
                                    put("baseUrl", "");
                                    put("authorizationEndpoint", "http://localhost/auth");
                                    put("tokenEndpoint", "http://localhost/token");
                                    put("userInfoUrl", "http://localhost/userinfo");
                                    put(
                                            "jwkSetURL",
                                            "http://localhost:"
                                                    + jwkServer.getAddress().getPort()
                                                    + "/.well-known/jwks.json");
                                    put("issuer", ISSUER);
                                    put(
                                            "introspectionEndpoint",
                                            "http://localhost:"
                                                    + introspectionServer
                                                            .getAddress()
                                                            .getPort()
                                                    + "/introspect");
                                    put("clientId", CLIENT_ID);
                                    put("clientSecret", "secret");
                                    put("scopes", new String[] {"openid"});
                                    put("additionalAuthorizationParameters", new String[0]);
                                }
                            })
                            .to(OidcConnectionImpl.Config.class),
                    null);

            // Create handler with online validation enabled
            OidcBearerAuthenticationHandler.Config onlineConfig = Converters.standardConverter()
                    .convert(new java.util.HashMap<String, Object>() {
                        {
                            put("path", new String[] {"/"});
                            put("idp", "oidc-bearer");
                            put("connectionName", "test-connection-introspection");
                            put("onlineValidation", true);
                            put("acceptedClientIds", new String[] {CLIENT_ID});
                            put("requiredScopes", new String[] {"openid"});
                            put("requiredAudiences", new String[] {"test-audience"});
                            put("cacheTtlSeconds", 300L);
                            put("cacheMaxSize", 1000);
                            put("service.ranking", 0);
                        }
                    })
                    .to(OidcBearerAuthenticationHandler.Config.class);

            List<ClientConnection> connectionsWithIntrospection = new ArrayList<>(connections);
            connectionsWithIntrospection.add(connectionWithIntrospection);

            // Add processor for introspection connection
            UserInfoProcessor introspectionProcessor = createMockUserInfoProcessor("test-connection-introspection");
            List<UserInfoProcessor> processorsWithIntrospection = new ArrayList<>(userInfoProcessors);
            processorsWithIntrospection.add(introspectionProcessor);

            OidcBearerAuthenticationHandler onlineHandler = new OidcBearerAuthenticationHandler(
                    bundleContext, connectionsWithIntrospection, processorsWithIntrospection, onlineConfig);

            // Use any token - online validation doesn't parse JWT
            String token = "opaque-token-12345";
            when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

            AuthenticationInfo authInfo = onlineHandler.extractCredentials(request, response);

            assertNotNull(authInfo, "Should return AuthenticationInfo for valid token (online)");
            assertEquals(SUBJECT, authInfo.getUser());
        } finally {
            introspectionServer.stop(0);
        }
    }

    @Test
    void testExtractCredentials_OnlineValidation_InactiveToken() throws Exception {
        // Create a mock introspection endpoint that returns inactive token
        HttpServer introspectionServer = HttpServer.create(new InetSocketAddress(0), 0);
        introspectionServer.createContext("/introspect", exchange -> {
            String responseJson = "{\"active\": false}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, responseJson.getBytes().length);
            exchange.getResponseBody().write(responseJson.getBytes());
            exchange.getResponseBody().close();
        });
        introspectionServer.start();

        try {
            // Create connection with introspection endpoint
            OidcConnectionImpl connectionWithIntrospection = new OidcConnectionImpl(
                    Converters.standardConverter()
                            .convert(new java.util.HashMap<String, Object>() {
                                {
                                    put("name", "test-connection-introspection");
                                    put("baseUrl", "");
                                    put("authorizationEndpoint", "http://localhost/auth");
                                    put("tokenEndpoint", "http://localhost/token");
                                    put("userInfoUrl", "http://localhost/userinfo");
                                    put(
                                            "jwkSetURL",
                                            "http://localhost:"
                                                    + jwkServer.getAddress().getPort()
                                                    + "/.well-known/jwks.json");
                                    put("issuer", ISSUER);
                                    put(
                                            "introspectionEndpoint",
                                            "http://localhost:"
                                                    + introspectionServer
                                                            .getAddress()
                                                            .getPort()
                                                    + "/introspect");
                                    put("clientId", CLIENT_ID);
                                    put("clientSecret", "secret");
                                    put("scopes", new String[] {"openid"});
                                    put("additionalAuthorizationParameters", new String[0]);
                                }
                            })
                            .to(OidcConnectionImpl.Config.class),
                    null);

            OidcBearerAuthenticationHandler.Config onlineConfig = Converters.standardConverter()
                    .convert(new java.util.HashMap<String, Object>() {
                        {
                            put("path", new String[] {"/"});
                            put("idp", "oidc-bearer");
                            put("connectionName", "test-connection-introspection");
                            put("onlineValidation", true);
                            put("acceptedClientIds", new String[] {CLIENT_ID});
                            put("requiredScopes", new String[] {"openid"});
                            put("requiredAudiences", new String[] {"test-audience"});
                            put("cacheTtlSeconds", 300L);
                            put("cacheMaxSize", 1000);
                            put("service.ranking", 0);
                        }
                    })
                    .to(OidcBearerAuthenticationHandler.Config.class);

            List<ClientConnection> connectionsWithIntrospection = new ArrayList<>(connections);
            connectionsWithIntrospection.add(connectionWithIntrospection);

            // Add processor for introspection connection
            UserInfoProcessor introspectionProcessor = createMockUserInfoProcessor("test-connection-introspection");
            List<UserInfoProcessor> processorsWithIntrospection = new ArrayList<>(userInfoProcessors);
            processorsWithIntrospection.add(introspectionProcessor);

            OidcBearerAuthenticationHandler onlineHandler = new OidcBearerAuthenticationHandler(
                    bundleContext, connectionsWithIntrospection, processorsWithIntrospection, onlineConfig);

            String token = "inactive-token";
            when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

            AuthenticationInfo authInfo = onlineHandler.extractCredentials(request, response);

            assertNull(authInfo, "Should return null for inactive token");
        } finally {
            introspectionServer.stop(0);
        }
    }

    @Test
    void testExtractCredentials_WithUserInfoFetch() throws Exception {
        // Create a mock UserInfo endpoint
        HttpServer userInfoServer = HttpServer.create(new InetSocketAddress(0), 0);
        userInfoServer.createContext("/userinfo", exchange -> {
            String userInfoJson = "{"
                    + "\"sub\": \"" + SUBJECT + "\","
                    + "\"name\": \"John Doe\","
                    + "\"given_name\": \"John\","
                    + "\"family_name\": \"Doe\","
                    + "\"email\": \"john.doe@example.com\","
                    + "\"preferred_username\": \"johndoe\""
                    + "}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, userInfoJson.getBytes().length);
            exchange.getResponseBody().write(userInfoJson.getBytes());
            exchange.getResponseBody().close();
        });
        userInfoServer.start();

        try {
            // Create connection with userInfo endpoint
            OidcConnectionImpl connectionWithUserInfo = new OidcConnectionImpl(
                    Converters.standardConverter()
                            .convert(new java.util.HashMap<String, Object>() {
                                {
                                    put("name", "test-connection-userinfo");
                                    put("baseUrl", "");
                                    put("authorizationEndpoint", "http://localhost/auth");
                                    put("tokenEndpoint", "http://localhost/token");
                                    put(
                                            "userInfoUrl",
                                            "http://localhost:"
                                                    + userInfoServer
                                                            .getAddress()
                                                            .getPort()
                                                    + "/userinfo");
                                    put(
                                            "jwkSetURL",
                                            "http://localhost:"
                                                    + jwkServer.getAddress().getPort()
                                                    + "/.well-known/jwks.json");
                                    put("issuer", ISSUER);
                                    put("introspectionEndpoint", "");
                                    put("clientId", CLIENT_ID);
                                    put("clientSecret", "secret");
                                    put("scopes", new String[] {"openid", "profile"});
                                    put("additionalAuthorizationParameters", new String[0]);
                                }
                            })
                            .to(OidcConnectionImpl.Config.class),
                    null);

            // Create handler with fetchUserInfo enabled
            OidcBearerAuthenticationHandler.Config userInfoConfig = Converters.standardConverter()
                    .convert(new java.util.HashMap<String, Object>() {
                        {
                            put("path", new String[] {"/"});
                            put("idp", "oidc-bearer");
                            put("connectionName", "test-connection-userinfo");
                            put("onlineValidation", false);
                            put("fetchUserInfo", true);
                            put("acceptedClientIds", new String[] {CLIENT_ID});
                            put("requiredScopes", new String[] {"openid"});
                            put("requiredAudiences", new String[] {"test-audience"});
                            put("cacheTtlSeconds", 300L);
                            put("cacheMaxSize", 1000);
                            put("service.ranking", 0);
                        }
                    })
                    .to(OidcBearerAuthenticationHandler.Config.class);

            List<ClientConnection> connectionsWithUserInfo = new ArrayList<>(connections);
            connectionsWithUserInfo.add(connectionWithUserInfo);

            // Add processor for userInfo connection
            UserInfoProcessor userInfoConnProcessor = createMockUserInfoProcessor("test-connection-userinfo");
            List<UserInfoProcessor> processorsWithUserInfo = new ArrayList<>(userInfoProcessors);
            processorsWithUserInfo.add(userInfoConnProcessor);

            OidcBearerAuthenticationHandler handlerWithUserInfo = new OidcBearerAuthenticationHandler(
                    bundleContext, connectionsWithUserInfo, processorsWithUserInfo, userInfoConfig);

            String token = createValidToken();
            when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

            AuthenticationInfo authInfo = handlerWithUserInfo.extractCredentials(request, response);

            assertNotNull(authInfo, "Should return AuthenticationInfo with user info");
            assertEquals(SUBJECT, authInfo.getUser());

            // Verify that UserInfo data was fetched and merged
            OidcAuthCredentials credentials =
                    (OidcAuthCredentials) authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
            assertNotNull(credentials);
            assertEquals("John Doe", credentials.getAttribute("name"));
            assertEquals("John", credentials.getAttribute("given_name"));
            assertEquals("Doe", credentials.getAttribute("family_name"));
            assertEquals("john.doe@example.com", credentials.getAttribute("email"));
            assertEquals("johndoe", credentials.getAttribute("preferred_username"));
        } finally {
            userInfoServer.stop(0);
        }
    }

    @Test
    void testExtractCredentials_WithUserInfoDisabled() throws Exception {
        // Test that fetchUserInfo=false doesn't fetch userInfo

        OidcBearerAuthenticationHandler.Config userInfoConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("fetchUserInfo", false); // Disabled for this test
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler handler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, userInfoConfig);

        String token = createValidToken();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNotNull(authInfo, "Should return AuthenticationInfo");
        assertEquals(SUBJECT, authInfo.getUser());

        // Verify that only token claims are present (no UserInfo fetch)
        OidcAuthCredentials credentials =
                (OidcAuthCredentials) authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
        assertNotNull(credentials);
        // Token contains name and email from createToken method
        assertEquals("Test User", credentials.getAttribute("name"));
        assertEquals("test@example.com", credentials.getAttribute("email"));
        // But should NOT have UserInfo-specific fields like given_name, family_name
        assertNull(credentials.getAttribute("given_name"));
    }

    @Test
    void testExtractCredentials_TokenWithoutSubject() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                // No subject
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claimsSet);
        signedJWT.sign(signer);

        String token = signedJWT.serialize();
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = handler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null for token without subject");
    }

    @Test
    void testExtractCredentials_ValidClientId() throws Exception {
        // Create handler with accepted client IDs
        OidcBearerAuthenticationHandler.Config clientIdConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID, "another-client-id"});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler clientIdHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, clientIdConfig);

        // Create token with client_id claim
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience("test-audience")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID)
                .claim("scope", "openid")
                .claim("name", "Test User")
                .claim("email", "test@example.com")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claimsSet);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = clientIdHandler.extractCredentials(request, response);

        assertNotNull(authInfo, "Should accept token with valid client ID");
        assertEquals(SUBJECT, authInfo.getUser());
    }

    @Test
    void testExtractCredentials_InvalidClientId() throws Exception {
        // Create handler with accepted client IDs that don't match the token
        OidcBearerAuthenticationHandler.Config clientIdConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {"different-client-id", "another-client-id"});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler clientIdHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, clientIdConfig);

        // Create token with client_id claim that doesn't match accepted client IDs
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(CLIENT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID)
                .claim("name", "Test User")
                .claim("email", "test@example.com")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claimsSet);
        signedJWT.sign(signer);
        String token = signedJWT.serialize();

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = clientIdHandler.extractCredentials(request, response);

        assertNull(authInfo, "Should reject token with invalid client ID");
    }

    @Test
    void testExtractCredentials_ValidScope() throws Exception {
        // Create handler with required scopes
        OidcBearerAuthenticationHandler.Config scopeConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"read", "write"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler scopeHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, scopeConfig);

        // Create token with scopes
        String token = createTokenWithScopes("read write admin");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = scopeHandler.extractCredentials(request, response);

        assertNotNull(authInfo, "Should accept token with valid scope");
        assertEquals(SUBJECT, authInfo.getUser());
    }

    @Test
    void testExtractCredentials_InvalidScope() throws Exception {
        // Create handler with required scopes
        OidcBearerAuthenticationHandler.Config scopeConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"admin", "superuser"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler scopeHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, scopeConfig);

        // Create token with different scopes
        String token = createTokenWithScopes("read write");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = scopeHandler.extractCredentials(request, response);

        assertNull(authInfo, "Should reject token without required scopes");
    }

    @Test
    void testExtractCredentials_PartialScopes() throws Exception {
        // Create handler that requires multiple scopes
        OidcBearerAuthenticationHandler.Config scopeConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"read", "write", "admin"});
                        put("requiredAudiences", new String[] {"test-audience"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler scopeHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, scopeConfig);

        // Create token with only some of the required scopes (missing "admin")
        String token = createTokenWithScopes("read write");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = scopeHandler.extractCredentials(request, response);

        assertNull(authInfo, "Should reject token that has only some but not all required scopes");
    }

    @Test
    void testConfiguration_EmptyScopeValue() {
        // Create handler configuration with an empty scope value
        OidcBearerAuthenticationHandler.Config scopeConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("requiredScopes", new String[] {"read", "", "write"});
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        // Should throw IllegalArgumentException when trying to create handler with empty scope value
        assertThrows(
                IllegalArgumentException.class,
                () -> new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, scopeConfig),
                "Should reject configuration with empty scope values");
    }

    // Helper methods

    private String createTokenWithScopes(String scopes) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience("test-audience")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID)
                .claim("scope", scopes)
                .claim("name", "Test User")
                .claim("email", "test@example.com")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private HttpServer createJwkServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
            String response = jwkSet.toString();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        });
        server.start();
        return server;
    }

    private String createValidToken() throws JOSEException {
        return createToken(SUBJECT, new Date(System.currentTimeMillis() + 3600000));
    }

    private String createToken(String subject, Date expiration) throws JOSEException {
        return createTokenWithIssuerAndSubject(ISSUER, subject, expiration);
    }

    private String createTokenWithIssuer(String issuer) throws JOSEException {
        return createTokenWithIssuerAndSubject(issuer, SUBJECT, new Date(System.currentTimeMillis() + 3600000));
    }

    private String createTokenWithIssuerAndSubject(String issuer, String subject, Date expiration)
            throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience("test-audience") // Default audience for tests
                .expirationTime(expiration)
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID) // Required for client ID validation
                .claim("scope", "openid") // Required scope for tests
                .claim("name", "Test User")
                .claim("email", "test@example.com")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Test
    void testExtractCredentials_ValidAudience() throws Exception {
        // Configure handler with required audiences
        OidcBearerAuthenticationHandler.Config audienceConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("fetchUserInfo", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"test-audience", "api://other"}); // Required audiences
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler audienceHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, audienceConfig);

        String token = createValidToken(); // Token with test-audience
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = audienceHandler.extractCredentials(request, response);

        assertNotNull(authInfo, "Should return AuthenticationInfo for valid audience");
        assertEquals(SUBJECT, authInfo.getUser());
    }

    @Test
    void testExtractCredentials_InvalidAudience() throws Exception {
        // Configure handler with required audiences
        OidcBearerAuthenticationHandler.Config audienceConfig = Converters.standardConverter()
                .convert(new java.util.HashMap<String, Object>() {
                    {
                        put("path", new String[] {"/"});
                        put("idp", "oidc-bearer");
                        put("connectionName", "test-connection");
                        put("onlineValidation", false);
                        put("fetchUserInfo", false);
                        put("acceptedClientIds", new String[] {CLIENT_ID});
                        put("requiredScopes", new String[] {"openid"});
                        put("requiredAudiences", new String[] {"api://different"}); // Required audiences
                        put("cacheTtlSeconds", 300L);
                        put("cacheMaxSize", 1000);
                        put("service.ranking", 0);
                    }
                })
                .to(OidcBearerAuthenticationHandler.Config.class);

        OidcBearerAuthenticationHandler audienceHandler =
                new OidcBearerAuthenticationHandler(bundleContext, connections, userInfoProcessors, audienceConfig);

        String token = createValidToken(); // Token with test-audience
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        AuthenticationInfo authInfo = audienceHandler.extractCredentials(request, response);

        assertNull(authInfo, "Should return null for invalid audience");
    }
}
