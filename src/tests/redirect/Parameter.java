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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles XSS via redirect provided via a GET parameter.
 */
public class Parameter extends HttpServlet {
  @VisibleForTesting
  static final String ECHOED_PARAM = "url";

  private enum Check {
    NONE,
    NOSTARTSWITHJS
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String pathInfo = Strings.nullToEmpty(request.getPathInfo());
    if (pathInfo.startsWith("/url/")) {
      // /redirect/parameter/url/a/b/c?x=y  gets redirected to /a/b/c?x=y
      // on the same host and port
      String target = pathInfo.substring(4);
      if (request.getQueryString() != null) {
        target += "?" + request.getQueryString();
      }
      Responses.sendRedirect(response, target);
    } else if (!echoedParam.isEmpty()) {
      // /redirect/parameter?url=......  gets redirected to the specified
      // url, which can either be relative or absolute
      Check check = pathInfo.isEmpty() 
          ? Check.NONE : Check.valueOf(pathInfo.toUpperCase().substring(1));
      switch(check) {
        case NONE:
          Responses.sendRedirect(response, echoedParam);
          break;
        case NOSTARTSWITHJS:
          handleNoStartWithJs(echoedParam, response);
          break;
      }
    } else {
      Responses.sendError(response, "Provide target url via url parameter", 400);
    }
  }

  private void handleNoStartWithJs(String param, HttpServletResponse response) throws IOException {
    if (param.startsWith("javascript")) {
      Responses.sendError(response, "Cannot redirect to javascript!", 400);
    } else {
      Responses.sendRedirect(response, param);
    }
  }
}
