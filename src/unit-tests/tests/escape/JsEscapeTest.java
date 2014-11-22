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

package com.google.testing.security.firingrange.tests.escape;

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
 * Tests for {@link JsEscape}.
 */
@RunWith(JUnit4.class)
public class JsEscapeTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
  }

  @Test
  public void doesNotOverEscapeSingleQuotes() throws IOException {
    when(request.getPathInfo()).thenReturn("escapeHtml/body");
    when(request.getParameter(JsEscape.ECHOED_PARAM)).thenReturn("foo\'");
    when(response.getWriter()).thenReturn(writer);


    new JsEscape().service(request, response);
    verify(response).setStatus(200);
    verify(writer).write(""
        + "<html>\n"
        + "  <body>\n"
        + "    foo\\'\n"
        + "  </body>\n"
        + "</html>");
  }
}
