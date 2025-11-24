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

class RedirectHelperTest {

    @Test
    void testFindLongestPathMatchingWithValidPaths() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b/c", result);
    }

    @Test
    void testFindLongestPathMatchingWithNoMatchingPath() {
        String[] paths = {"/x/y", "/z"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyPaths() {
        String[] paths = {};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithNullUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, null);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, "");
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSinglePath() {
        String[] paths = {"/a"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a", result);
    }

    @Test
    void testFindLongestPathMatchingWithInvalidUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "invalid-url";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSibling() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c_sibling/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b", result);
    }

    @Test
    void testValidateRedirectWithValidRelativeUrl() throws OAuthEntryPointException {
        // Should not throw exception for valid relative URLs
        RedirectHelper.validateRedirect("/valid/path");
        RedirectHelper.validateRedirect("/another/valid/path");
        RedirectHelper.validateRedirect("/");
    }

    @Test
    void testValidateRedirectWithNullUrl() throws OAuthEntryPointException {
        // Should not throw exception for null URL
        RedirectHelper.validateRedirect(null);
    }

    @Test
    void testValidateRedirectWithEmptyUrl() throws OAuthEntryPointException {
        // Should not throw exception for empty URL
        RedirectHelper.validateRedirect("");
    }

    @Test
    void testValidateRedirectWithInvalidAbsoluteUrl() {
        // Should throw exception for absolute URLs (cross-site redirect)
        OAuthEntryPointException exception = assertThrows(
                OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect("http://example.com/path"));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void testValidateRedirectWithInvalidHttpsUrl() {
        // Should throw exception for HTTPS URLs (cross-site redirect)
        OAuthEntryPointException exception = assertThrows(
                OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect("https://example.com/path"));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void testValidateRedirectWithInvalidProtocolUrl() {
        // Should throw exception for other protocols
        OAuthEntryPointException exception = assertThrows(
                OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect("ftp://example.com/path"));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void testValidateRedirectWithJavaScriptUrl() {
        // Should throw exception for javascript: URLs
        OAuthEntryPointException exception = assertThrows(
                OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect("javascript:alert('xss')"));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }
}
