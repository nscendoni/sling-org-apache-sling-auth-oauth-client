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

import java.util.Map;

import org.jetbrains.annotations.NotNull;
import org.osgi.util.converter.Converters;

public class MockOidcConnection extends OidcConnectionImpl {
    public static final MockOidcConnection DEFAULT_CONNECTION = new MockOidcConnection(
            new String[] {"openid"}, "mock-oidc", "client-id", "client-secret", "https://example.com", new String[0]);

    public MockOidcConnection(
            String[] scopes,
            String name,
            String clientId,
            String clientSecret,
            String baseUrl,
            String[] additionalAuthorizationParameters) {
        super(
                Converters.standardConverter()
                        .convert(Map.of(
                                "name",
                                name,
                                "baseUrl",
                                baseUrl,
                                "clientId",
                                clientId,
                                "clientSecret",
                                clientSecret,
                                "scopes",
                                scopes,
                                "additionalAuthorizationParameters",
                                additionalAuthorizationParameters))
                        .to(Config.class),
                null);
    }

    public MockOidcConnection(
            String[] scopes,
            String name,
            String clientId,
            String clientSecret,
            String baseUrl,
            String[] additionalAuthorizationParameters,
            OidcProviderMetadataRegistry metadataRegistry) {
        super(
                Converters.standardConverter()
                        .convert(Map.of(
                                "name",
                                name,
                                "baseUrl",
                                baseUrl,
                                "clientId",
                                clientId,
                                "clientSecret",
                                clientSecret,
                                "scopes",
                                scopes,
                                "additionalAuthorizationParameters",
                                additionalAuthorizationParameters))
                        .to(Config.class),
                metadataRegistry);
    }

    @Override
    public @NotNull String authorizationEndpoint() {
        return baseUrl() + "/authorize";
    }

    @Override
    public @NotNull String tokenEndpoint() {
        return baseUrl() + "/token";
    }
}
