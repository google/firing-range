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

package com.google.testing.security.firingrange.tests.urldom;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides open redirection service except to URI with JavaScript URI scheme.
 */
public class Redirect extends HttpServlet {
  @VisibleForTesting static final String REDIRECT_PARAM = "url";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String redirectParam = Strings.nullToEmpty(request.getParameter(REDIRECT_PARAM));

    if (!redirectParam.isEmpty()) {
      Responses.sendRedirect(response, redirectParam);

    } else {
      Responses.sendError(response, "Provide target url via url parameter", 400);
    }
  }
}
