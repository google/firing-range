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

import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Splitter;
import com.google.common.net.HttpHeaders;
import java.io.PrintWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.AdditionalMatchers;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;

/** Tests for {@link LeakedHttpOnlyCookie}. */
@RunWith(JUnit4.class)
public final class LeakedHttpOnlyCookieTest {
  private final HttpServletRequest request = mock(HttpServletRequest.class);
  private final HttpServletResponse response = mock(HttpServletResponse.class);
  private final PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws Exception {
    when(response.getWriter()).thenReturn(writer);
  }

  @Test
  public void doGet_leakedCookiePage_setsCookieAndReturnsItInResponse() throws Exception {
    ArgumentCaptor<String> setCookieHeader = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(response)
        .setHeader(Matchers.eq(HttpHeaders.SET_COOKIE), setCookieHeader.capture());
    when(request.getPathInfo()).thenReturn("/leakedcookie");

    new LeakedHttpOnlyCookie().doGet(request, response);

    String cookieValue = extractCookieValue(setCookieHeader.getValue());
    verify(response).setHeader(Matchers.eq(HttpHeaders.SET_COOKIE), contains("HttpOnly"));
    verify(writer).write(contains(cookieValue));
  }

  @Test
  public void doGet_leakedInResource_setsCookieAndDoesntReturnItInResponse() throws Exception {
    ArgumentCaptor<String> setCookieHeader = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(response)
        .setHeader(Matchers.eq(HttpHeaders.SET_COOKIE), setCookieHeader.capture());
    when(request.getPathInfo()).thenReturn("/leakedinresource");

    new LeakedHttpOnlyCookie().doGet(request, response);

    String cookieValue = extractCookieValue(setCookieHeader.getValue());
    verify(writer).write(AdditionalMatchers.not(contains(cookieValue)));
  }

  @Test
  public void doGet_whenRequestingResourcePath_leaksCookie() throws Exception {
    Cookie cookie = new Cookie(LeakedHttpOnlyCookie.COOKIE_NAME, "327498279481");
    Cookie[] cookies = new Cookie[1];
    cookies[0] = cookie;
    when(request.getPathInfo()).thenReturn("/leakedcookie.js");
    when(request.getCookies()).thenReturn(cookies);

    new LeakedHttpOnlyCookie().doGet(request, response);
    verify(writer).write(contains("327498279481"));
  }


  @Test
  public void doGet_whenCalledTwice_randomizesCookieValue() throws Exception {
    ArgumentCaptor<String> setCookieHeader = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(response)
        .setHeader(Matchers.eq(HttpHeaders.SET_COOKIE), setCookieHeader.capture());
    when(request.getPathInfo()).thenReturn("/leakedcookie");

    new LeakedHttpOnlyCookie().doGet(request, response);
    String cookieValue1 = extractCookieValue(setCookieHeader.getValue());
    new LeakedHttpOnlyCookie().doGet(request, response);
    String cookieValue2 = extractCookieValue(setCookieHeader.getValue());

    // This might fail with a very low probability because the two cookie values might be the same
    // by random. However, both values are generated from 8 bytes of random. The chances should be
    // low enough.
    assertNotEquals(cookieValue1, cookieValue2);
  }

  private static String extractCookieValue(String rawSetCookieHeader) {
    String cookieNameAndValue = Splitter.on(';').splitToList(rawSetCookieHeader).get(0);
    return Splitter.on('=').splitToList(cookieNameAndValue).get(1);
  }
}
