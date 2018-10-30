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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HttpHeaders;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import java.util.Random;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet setting an httpOnly cookie and leaking it in the body of the same response.
 *
 * <p>The actual value of the cookie is a random base64 string.
 */
public class LeakedHttpOnlyCookie extends HttpServlet {
  private static final String BASE_TEMPLATE = "leakedcookie.tmpl";
  private static final String JS_TEMPLATE = "leakedcookiejs.tmpl";
  private static final String RESOURCE_TEMPLATE = "leakedcookieresource.tmpl";
  @VisibleForTesting static final String COOKIE_NAME = "my_secret_cookie";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String pathInfo = request.getPathInfo().substring(1);
    String cookieValue = createRandomString();

    switch (pathInfo) {
      case "leakedcookie":
        response.setHeader(
            HttpHeaders.SET_COOKIE, String.format("%s=%s; HttpOnly", COOKIE_NAME, cookieValue));
        Responses.sendNormalPage(
            response,
            Templates.getTemplate(BASE_TEMPLATE, this.getClass())
                .replace("%%COOKIE%%", cookieValue));
        break;
      case "leakedinresource":
        response.setHeader(
            HttpHeaders.SET_COOKIE, String.format("%s=%s; HttpOnly", COOKIE_NAME, cookieValue));
        Responses.sendNormalPage(
            response, Templates.getTemplate(RESOURCE_TEMPLATE, this.getClass()));
        break;
      case "leakedcookie.js":
        cookieValue = getCookieValueByName(request, COOKIE_NAME).orElse("");
        Responses.sendJavaScript(
            response,
            Templates.getTemplate(JS_TEMPLATE, this.getClass()).replace("%%COOKIE%%", cookieValue));
        break;
      default: // fall out
    }
  }

  private Optional<String> getCookieValueByName(HttpServletRequest request, String name) {
    Cookie[] cookies = request.getCookies();
    for (int i = 0; i < cookies.length; i++) {
      if (cookies[i].getName().equals(name)) {
        return Optional.of(cookies[i].getValue());
      }
    }
    return Optional.empty();
  }

  private String createRandomString() {
    Random random = new Random();
    byte[] randomByteBuffer = new byte[8];
    random.nextBytes(randomByteBuffer);
    return Base64.getEncoder().encodeToString(randomByteBuffer);
  }
}
