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

package com.google.testing.security.firingrange.tests.reflected;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests for {@link Url}.
 */
@RunWith(JUnit4.class)
public class UrlTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Before
  public void setUpMocks() throws IOException {
    when(request.getPathInfo()).thenReturn("/href");
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));    
  }

  @Test
  public void errorsOnBadUrl() throws IOException {
    when(request.getParameter(Url.ECHOED_PARAM)).thenReturn("foo\"bar");
    new Url().service(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void acceptsUrl() throws IOException {
    when(request.getParameter(Url.ECHOED_PARAM)).thenReturn("http://google.com");
    new Url().service(request, response);
    verify(response).setStatus(200);
  }
}
