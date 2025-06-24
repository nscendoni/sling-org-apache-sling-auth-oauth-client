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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ResolvedOAuthConnectionTest {

    // Write test for resolve(@NotNull ClientConnection connection)
    // This test should cover both OAuthConnectionImpl and OidcConnectionImpl
    // and ensure that the resolved connection has all parameters materialised correctly.
    @Test
    void testResolveOAuthConnection_OAuth() {
        // Create an instance of OAuthConnectionImpl
        // Mock the Config interface
        OAuthConnectionImpl.Config mockConfig = mock(OAuthConnectionImpl.Config.class);

        // Stub the methods
        when(mockConfig.name()).thenReturn("TestOAuthConnection");
        when(mockConfig.authorizationEndpoint()).thenReturn("https://auth.example.com/oauth/authorize");
        when(mockConfig.tokenEndpoint()).thenReturn("https://auth.example.com/oauth/token");
        when(mockConfig.clientId()).thenReturn("test-client-id");
        when(mockConfig.clientSecret()).thenReturn("test-client-secret");
        when(mockConfig.scopes()).thenReturn(new String[] {"scope1", "scope2"});
        when(mockConfig.additionalAuthorizationParameters())
                .thenReturn(new String[] {"param1=value1", "param2=value2"});

        // Create an instance of OAuthConnectionImpl using the mocked Config
        OAuthConnectionImpl oauthConnection = new OAuthConnectionImpl(mockConfig);

        // Resolve the connection
        ResolvedConnection resolved = ResolvedOAuthConnection.resolve(oauthConnection);

        // Assert that the resolved connection has all parameters materialised correctly
        assertTrue(resolved instanceof ResolvedOAuthConnection);
        assertEquals("TestOAuthConnection", resolved.name());
        assertEquals("https://auth.example.com/oauth/authorize", resolved.authorizationEndpoint());
        assertEquals("https://auth.example.com/oauth/token", resolved.tokenEndpoint());
        assertEquals("test-client-id", resolved.clientId());
        assertEquals("test-client-secret", resolved.clientSecret());
        assertArrayEquals(new String[] {"scope1", "scope2"}, resolved.scopes().toArray());
        assertArrayEquals(
                new String[] {"param1=value1", "param2=value2"},
                resolved.additionalAuthorizationParameters().toArray());
    }

    @Test
    void testResolveOidcConnection_OIDC() {
        // mock the OidcConnectionImpl
        OidcConnectionImpl mockOidcConnection = mock(OidcConnectionImpl.class);
        when(mockOidcConnection.name()).thenReturn("TestOidcConnection");
        when(mockOidcConnection.authorizationEndpoint()).thenReturn("https://auth.example.com/oidc/authorize");
        when(mockOidcConnection.tokenEndpoint()).thenReturn("https://auth.example.com/oidc/token");
        when(mockOidcConnection.clientId()).thenReturn("test-oidc-client-id");
        when(mockOidcConnection.clientSecret()).thenReturn("test-oidc-client-secret");
        when(mockOidcConnection.scopes()).thenReturn(new String[] {"openid", "profile"});
        when(mockOidcConnection.additionalAuthorizationParameters())
                .thenReturn(new String[] {"param1=value1", "param2=value2"});

        // Resolve the connection
        ResolvedConnection resolved = ResolvedOAuthConnection.resolve(mockOidcConnection);

        // Assert that the resolved connection has all parameters materialised correctly
        assertTrue(resolved instanceof ResolvedOAuthConnection);
        assertEquals("TestOidcConnection", resolved.name());
        assertEquals("https://auth.example.com/oidc/authorize", resolved.authorizationEndpoint());
        assertEquals("https://auth.example.com/oidc/token", resolved.tokenEndpoint());
        assertEquals("test-oidc-client-id", resolved.clientId());
        assertEquals("test-oidc-client-secret", resolved.clientSecret());
        assertArrayEquals(new String[] {"openid", "profile"}, resolved.scopes().toArray());
        assertArrayEquals(
                new String[] {"param1=value1", "param2=value2"},
                resolved.additionalAuthorizationParameters().toArray());
    }
}
