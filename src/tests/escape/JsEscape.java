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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles reflected XSS with the payload escaped in JavaScript.
 */
public class JsEscape extends HttpServlet {
  private static final Logger logger = Logger.getLogger(ServersideEscape.class.getCanonicalName());

  @VisibleForTesting
  static final String ECHOED_PARAM = "q";

  private String stringEscape(String value) {
    return value.replace("\\", "\\\\")
        .replace("'", "\\'");
  }

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String template;
    try {
      template = Templates.getTemplate(request, getClass());
    } catch (IOException e) {
      logger.fine(e.toString());
      Responses.sendError(response, e.getMessage(), 400);
      return;
    }    
    Responses.sendXssed(response, Templates.replacePayload(template, stringEscape(echoedParam)));
  }
}
