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
package com.google.testing.security.firingrange.tests.cors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

/** Tests for {@link AllowNullOrigin}. */
@RunWith(JUnit4.class)
public final class AllowNullOriginTest {
  private static final AllowNullOrigin servlet = new AllowNullOrigin();
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Before
  public void setupResponseMock() throws IOException {
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
  }

  @Test
  public void doPost_givenOriginHeader_returnsVulnerableAccessControlHeaders() throws IOException {
    when(request.getHeader("Origin")).thenReturn("veryLong.google.domain.google.com");

    servlet.doPost(request, response);

    verify(response).setHeader("Access-Control-Allow-Origin", "null");
    verify(response).setHeader("Access-Control-Allow-Credentials", "true");
  }

  @Test
  public void doPost_withoutOriginHeader_returnsNoAccessControlHeaders() throws IOException {
    servlet.doPost(request, response);

    verify(response, never()).setHeader("Access-Control-Allow-Origin", "null");
    verify(response, never()).setHeader("Access-Control-Allow-Credentials", "true");
  }
}
