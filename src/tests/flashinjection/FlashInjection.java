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

package com.google.testing.security.firingrange.tests.flashinjection;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The servlet returns JSON and handles two endpoints one of which echoes a query parameter in the
 * beginning of the request, and the other does not.
 */
public class FlashInjection extends HttpServlet {

  private static final String CALLBACK_IS_ECHOED_BACK = "callbackIsEchoedBack";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String responseBody;
    String callback = request.getParameter("callback"); 
    if (request.getRequestURI().contains(CALLBACK_IS_ECHOED_BACK) && callback != null) {
      if (!Pattern.matches("^[a-zA-Z0-9]+$", callback)) {
        response.setStatus(500);
        return;
      }
      responseBody = callback + "({});";
    } else {
      responseBody = "func({});";
    }
    response.setContentType("application/json");
    response.setCharacterEncoding(UTF_8.name());
    response.setStatus(200);
    response.getWriter().write(responseBody);
    response.getWriter().flush();
  }
}
