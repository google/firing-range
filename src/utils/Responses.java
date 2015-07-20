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

import com.google.common.base.Preconditions;
import com.google.common.net.HttpHeaders;

import java.io.IOException;

import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletResponse;

/**
 * Utility class handling HTTP responses.
 */
@Immutable
public final class Responses {

  private Responses() {}

  /**
   * Sends a "normal" response, with all the standard headers. 
   */
  public static void sendNormalPage(HttpServletResponse response, String body) throws IOException {
    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate");
    response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    response.setDateHeader(HttpHeaders.EXPIRES, 0);
    response.setHeader(HttpHeaders.CONTENT_TYPE, "text/html; charset=utf-8");
    response.setStatus(200);
    response.getWriter().write(body);
  }

  /**
   * Sends an XSS response. 
   */
  public static void sendXssed(HttpServletResponse response, String body) throws IOException {
    sendXssed(response, body, "text/html; charset=utf-8");
  }

  /**
   * Sends an HTML XSSed response with the given status. 
   */
  public static void sendXssed(HttpServletResponse response, String body, int status)
      throws IOException {
    sendXssed(response, body, "text/html; charset=utf-8", status);
  }

  /**
   * Sends an XSS response of a given type. 
   */
  public static void sendXssed(HttpServletResponse response, String body, String contentType)
      throws IOException {
    sendXssed(response, body, contentType, 200);
  }

  /**
   * Sends an XSS response of a given type. 
   */
  public static void sendXssed(HttpServletResponse response, String body, String contentType,
      int status) throws IOException {
    response.setHeader(HttpHeaders.X_XSS_PROTECTION, "0");
    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate");
    response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    response.setDateHeader(HttpHeaders.EXPIRES, 0);
    response.setHeader(HttpHeaders.CONTENT_TYPE, contentType);
    response.setStatus(status);
    response.getWriter().write(body);
  }

  /**
   * Sends an error to the user with the given {@code status} and body.
   */
  public static void sendError(HttpServletResponse response, String body, int status)
      throws IOException {
    Preconditions.checkArgument(status > 300);
    response.setStatus(status);
    response.setHeader(HttpHeaders.CONTENT_TYPE, "text/plain");
    response.getWriter().write(Escaper.escapeHtml(body));
  }
  
  /**
   * Sends a response with the content type text/javascript.
   */
  public static void sendJavaScript(HttpServletResponse response, String body)
      throws IOException {
    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate");
    response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    response.setDateHeader(HttpHeaders.EXPIRES, 0);
    response.setHeader(HttpHeaders.CONTENT_TYPE, "text/javascript");
    response.setStatus(200);
    response.getWriter().write(body);
  }

  /**
   * Sends a redirect to the user.
   */
  public static void sendRedirect(HttpServletResponse response, String location) {
    response.setStatus(302);
    response.setHeader(HttpHeaders.LOCATION, location);
  }
}
