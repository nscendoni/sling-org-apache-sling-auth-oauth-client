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

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Service Provider Interface for token validation.
 * Implementations can provide different validation strategies (e.g., offline JWT validation, online introspection).
 */
public interface TokenValidator {

    /**
     * Returns the unique name of this token validator.
     *
     * @return the validator name
     */
    @NotNull
    String name();

    /**
     * Validates the given bearer token.
     *
     * @param token the bearer token to validate
     * @param connection the OIDC connection to use for validation
     * @return a TokenValidationResult containing the claims if valid, null otherwise
     */
    @Nullable
    TokenValidationResult validate(@NotNull String token, @NotNull ClientConnection connection);

    /**
     * Result of token validation containing the validated claims.
     */
    class TokenValidationResult {
        private final String subject;
        private final JWTClaimsSet claimsSet;

        public TokenValidationResult(@NotNull String subject, @NotNull JWTClaimsSet claimsSet) {
            this.subject = subject;
            this.claimsSet = claimsSet;
        }

        @NotNull
        public String getSubject() {
            return subject;
        }

        @NotNull
        public JWTClaimsSet getClaimsSet() {
            return claimsSet;
        }
    }
}
