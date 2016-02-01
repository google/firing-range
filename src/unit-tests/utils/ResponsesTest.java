/*
 * Copyright 2014 Google Inc. All rights reserved.
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

package com.google.testing.security.firingrange.utils;

import static org.mockito.Mockito.mock;

import com.google.common.net.HttpHeaders;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletResponse;

/**
 * Tests for {@link Responses}.
 */
@RunWith(JUnit4.class)
public class ResponsesTest {

  @Test
  public void addXssNone() throws IOException {
    HttpServletResponse response = mock(HttpServletResponse.class);
    Mockito.when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    Responses.sendXssed(response, "irrelevant");
    Mockito.verify(response).setHeader(HttpHeaders.X_XSS_PROTECTION, "0");
  }

  @Test
  public void sendsRedirectIsARedirect() {
    HttpServletResponse response = mock(HttpServletResponse.class);
    String redirectUrl = "redirectUrl";
    Responses.sendRedirect(response, redirectUrl);
    Mockito.verify(response).setStatus(302);
    Mockito.verify(response).setHeader("Location", redirectUrl);
  }
}
