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
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthTokenRefresherImplTest {

    private HttpServer mockServer;
    private String mockServerUrl;
    private OAuthTokenRefresherImpl refresher;
    private String originalRefreshToken = "old-refresh-token-456";

    @BeforeEach
    void setUp() throws IOException {
        // Create a simple HTTP server to mock the OAuth token endpoint
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();
        mockServerUrl = "http://localhost:" + port;
        mockServer.start();

        refresher = new OAuthTokenRefresherImpl();
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.stop(0);
        }
    }

    @Test
    void testRefreshTokensWithoutNewRefreshToken() {

        setupMockTokenEndpoint("new-access-token-123", null);

        OAuthTokens newTokens = refresher.refreshTokens(createMockConnection(), originalRefreshToken);

        assertThat(newTokens.accessToken())
                .as("new access token should be returned")
                .isEqualTo("new-access-token-123");

        assertThat(newTokens.refreshToken())
                .as("no token is returned when server does not provide a new one")
                .isNull();
    }

    @Test
    void testRefreshTokensWithNewRefreshToken() {

        setupMockTokenEndpoint("new-access-token-789", "new-refresh-token-xyz");

        OAuthTokens refreshedTokens = refresher.refreshTokens(createMockConnection(), originalRefreshToken);

        assertThat(refreshedTokens.accessToken())
                .as("new access token should be returned")
                .isEqualTo("new-access-token-789");

        assertThat(refreshedTokens.refreshToken())
                .as("new refresh token should be returned when server provides one")
                .isEqualTo("new-refresh-token-xyz");
    }

    private void setupMockTokenEndpoint(String accessToken, String refreshToken) {
        mockServer.createContext("/token", (HttpExchange exchange) -> {
            StringBuilder response = new StringBuilder();
            response.append("{\n");
            response.append("  \"access_token\": \"").append(accessToken).append("\",\n");
            response.append("  \"token_type\": \"Bearer\",\n");
            response.append("  \"expires_in\": 3600");
            if (refreshToken != null) {
                response.append(",\n");
                response.append("  \"refresh_token\": \"").append(refreshToken).append("\"");
            }
            response.append("\n}");

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] responseBytes = response.toString().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        });
    }

    private MockOidcConnection createMockConnection() {
        return new MockOidcConnection(
                new String[] {"openid"},
                "test-connection",
                "test-client-id",
                "test-client-secret",
                mockServerUrl,
                new String[0]);
    }
}
