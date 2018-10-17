/*
 * Copyright 2018 Google Inc. All rights reserved.
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
package com.google.testing.security.firingrange.tests.leakedcookie;

import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link LeakedHttpOnlyCookie}. */
@RunWith(JUnit4.class)
public final class LeakedHttpOnlyCookieTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Test
  public void doGet_always_setsCookieAndReturnsItInResponse() throws IOException {
    when(response.getWriter()).thenReturn(writer);
    new LeakedHttpOnlyCookie().doGet(request, response);
    verify(response).setStatus(200);
    verify(response)
        .setHeader("Set-Cookie", "my_secret_cookie=my-magic-cookie-shouldnt-be-leaked; HttpOnly");
    verify(writer).write(contains("my-magic-cookie-shouldnt-be-leaked"));
  }
}
