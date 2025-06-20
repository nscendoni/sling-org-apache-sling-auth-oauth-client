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
package org.apache.sling.auth.oauth_client;

import java.net.URI;

import org.apache.sling.auth.oauth_client.impl.MockOidcConnection;
import org.apache.sling.auth.oauth_client.impl.OAuthUris;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SlingContextExtension.class)
class OAuthUrisTest {

    private final SlingContext context = new SlingContext();

    @Test
    void testRedirectUri() {
        URI redirectUri =
                OAuthUris.getOAuthEntryPointUri(MockOidcConnection.DEFAULT_CONNECTION, context.request(), "/foo");

        assertThat(redirectUri)
                .as("redirect uri")
                .hasScheme("http")
                .hasHost("localhost")
                .hasNoPort()
                .hasPath("/system/sling/oauth/entry-point")
                .hasQuery("c=mock-oidc&redirect=/foo");
    }
}
