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

package com.google.testing.security.firingrange.tests.redirect;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests for {@link Parameter}.
 */
@RunWith(JUnit4.class)
public class ParameterTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Test
  public void errorsOnBadUrl() throws IOException {
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn(null);
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    new Parameter().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void sendsRedirectOnParameter() throws IOException {
    String urlValue = "https://google.com";
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn(urlValue);
    new Parameter().doGet(request, response);
    verify(response).setStatus(302);
    verify(response).setHeader(HttpHeaders.LOCATION, urlValue);
  }
  
  @Test
  public void sendsRedirectOnUrl() throws IOException {
    String pathInfo = "/url/a/b/c";
    String queryString = "author=fy";
    when(request.getPathInfo()).thenReturn(pathInfo);
    when(request.getQueryString()).thenReturn(queryString);
    new Parameter().doGet(request, response);
    verify(response).setStatus(302);
    verify(response).setHeader(HttpHeaders.LOCATION, 
        "/a/b/c?" + queryString);
  }

  @Test
  public void refusesJavascriptIfSoInstructed() throws IOException {
    String urlValue = "javascript://alert(1)";
    when(request.getPathInfo()).thenReturn("/NOSTARTSWITHJS");
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn(urlValue);
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    new Parameter().doGet(request, response);
    verify(response).setStatus(400);
  }
}
