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

import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;

//
// In terms of what typed objects we expose, there are a number of ways
//
// - expose Nimbus objects, which ties us to the library 'forever' ( or makes us break backwards
//   compatibility if we need to change to another library, like we did for the XSS APIU
// - create our own wrapper objects, which is nice for the consumer but a lot of duplicate work
// - pass Strings (or simple types like a StringToken which promises to hold valid JSON ) around
//   and ask consumers to parse them, while internally using the Nimbus SDK. This is the most
//   flexible, but also a bit wasteful
// - (?) can we do without exposing the actual tokens?

/**
 * Storage for OAuth Tokens
 *
 * <p>This service allows access to storing and retrieving OAuth tokens. It is the responsibility of the caller
 * to ensure that the tokens are valid.</p>
 *
 * <p>For methods that return {@link OAuthToken}, the state must be inspected before attempting to read the value.</p>
 */
public interface OAuthTokenStore {

    String PROPERTY_NAME_ACCESS_TOKEN = "access_token";
    String PROPERTY_NAME_REFRESH_TOKEN = "refresh_token";

    @NotNull
    OAuthToken getAccessToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver)
            throws OAuthException;

    @NotNull
    OAuthToken getRefreshToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver)
            throws OAuthException;

    void persistTokens(
            @NotNull ClientConnection connection, @NotNull ResourceResolver resolver, @NotNull OAuthTokens tokens)
            throws OAuthException;

    void clearAccessToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver)
            throws OAuthException;
}
