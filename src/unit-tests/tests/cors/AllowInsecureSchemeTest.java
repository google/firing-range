/*
 * Copyright 2017 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.google.testing.security.firingrange.tests.cors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link AllowInsecureScheme}. */
@RunWith(JUnit4.class)
public final class AllowInsecureSchemeTest {
  private static final String SCHEME = "https";
  private static final String DOMAIN = "www.google.com";
  private static final String URL = SCHEME + "://" + DOMAIN;
  private static final AllowInsecureScheme servlet = new AllowInsecureScheme();
  private final HttpServletRequest request = mock(HttpServletRequest.class);
  private final HttpServletResponse response = mock(HttpServletResponse.class);

  @Before
  public void setupMocks() throws IOException {
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    when(request.getScheme()).thenReturn(SCHEME);
    when(request.getServerName()).thenReturn(DOMAIN);
    when(request.getServerPort()).thenReturn(-1);
  }

  @Test
  public void doPost_withSameOrigin_allowsOrigin() throws IOException {
    when(request.getHeader("Origin")).thenReturn(URL);

    servlet.doPost(request, response);

    verify(response).setHeader("Access-Control-Allow-Origin", URL);
    verify(response).setHeader("Access-Control-Allow-Credentials", "true");
  }

  @Test
  public void doPost_withDifferentDomain_disallowsOrigin() throws IOException {
    when(request.getHeader("Origin")).thenReturn("https://foo.google.com/");

    servlet.doPost(request, response);

    verify(response).setHeader("Access-Control-Allow-Origin", URL);
    verify(response).setHeader("Access-Control-Allow-Credentials", "true");
  }

  @Test
  public void doPost_withDifferentScheme_allowsOrigin() throws IOException {
    when(request.getHeader("Origin")).thenReturn("http://" + DOMAIN);

    servlet.doPost(request, response);

    verify(response).setHeader("Access-Control-Allow-Origin", "http://" + DOMAIN);
    verify(response).setHeader("Access-Control-Allow-Credentials", "true");
  }
}
