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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

import javax.servlet.http.HttpServletRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mockito;

/**
 * Tests for {@link Requests}.
 */
@RunWith(JUnit4.class)
public class RequestsTest {
  @Test
  public void getBaseUrl_givenHttpSchemeAndNoPort_returnsBasicUrlWithoutPort() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    Mockito.when(request.getScheme()).thenReturn("http");
    Mockito.when(request.getServerName()).thenReturn("google.com");
    Mockito.when(request.getServerPort()).thenReturn(-1);
    assertEquals("http://google.com", Requests.getBaseUrl(request));
  }

  @Test
  public void getBaseUrl_givenHttpSchemeAndPort80_returnsBasicUrlWithoutPort() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    Mockito.when(request.getScheme()).thenReturn("http");
    Mockito.when(request.getServerName()).thenReturn("google.com");
    Mockito.when(request.getServerPort()).thenReturn(80);
    assertEquals("http://google.com", Requests.getBaseUrl(request));
  }

  @Test
  public void getBaseUrl_givenHttpsSchemeAndNoPort_returnsBasicUrlWithoutPort() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    Mockito.when(request.getScheme()).thenReturn("https");
    Mockito.when(request.getServerName()).thenReturn("google.com");
    Mockito.when(request.getServerPort()).thenReturn(-1);
    assertEquals("https://google.com", Requests.getBaseUrl(request));
  }

  @Test
  public void getBaseUrl_givenHttpsSchemeAndPort443_returnsBasicUrlWithoutPort() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    Mockito.when(request.getScheme()).thenReturn("https");
    Mockito.when(request.getServerName()).thenReturn("google.com");
    Mockito.when(request.getServerPort()).thenReturn(443);
    assertEquals("https://google.com", Requests.getBaseUrl(request));
  }

  @Test
  public void getBaseUrl_givenHttpsSchemeAndNonStandardPort_returnsBasicUrlWithPort() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    Mockito.when(request.getScheme()).thenReturn("https");
    Mockito.when(request.getServerName()).thenReturn("google.com");
    Mockito.when(request.getServerPort()).thenReturn(8000);
    assertEquals("https://google.com:8000", Requests.getBaseUrl(request));
  }
}
