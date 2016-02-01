/*
 * Copyright 2016 Google Inc. All rights reserved.
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

import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
 * Tests for {@link EscapedParameter}.
 */
@RunWith(JUnit4.class)
public class EscapedParameterTest {
  private EscapedParameter servlet = new EscapedParameter();
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(writer);    
  }

  @Test
  public void returnsOkByDefault() throws IOException {
    when(request.getPathInfo()).thenReturn("/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE");
    servlet.service(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void escapesSingleQuotes() throws IOException {
    when(request.getPathInfo()).thenReturn("/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE");
    String unescaped = "foo\"'";
    when(request.getParameter(EscapedParameter.ECHOED_PARAM)).thenReturn(unescaped);
    servlet.service(request, response);
    verify(response).setStatus(200);
    verify(writer, never()).write(contains(unescaped));
  }

  @Test
  public void escapesUnquotedAttribute() throws IOException {
    when(request.getPathInfo()).thenReturn("/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE");
    String unescaped = "a>foo";
    when(request.getParameter(EscapedParameter.ECHOED_PARAM)).thenReturn(unescaped);
    servlet.service(request, response);
    verify(response).setStatus(200);
    verify(writer, never()).write(contains(unescaped));
  }
}
