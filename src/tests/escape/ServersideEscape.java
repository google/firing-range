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

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles reflected XSS with serverside escaping of the payload.
 */
public class ServersideEscape extends HttpServlet {
  private static final Logger logger = Logger.getLogger(ServersideEscape.class.getCanonicalName());
  private static final String ECHOED_PARAM = "q";

  private String htmlEscape(String value) {
    return value.replace("<", "&lt;")
        .replace("&", "&amp;")
        .replace(">", "&gt;");
  }

  private String encodeURL(String value) {
    try {
      return URLEncoder.encode(value, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      return null;
    }
  }

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String pathInfo = request.getPathInfo().substring(1);
    String[] path = pathInfo.split("/");

    if (CharMatcher.is('/').countIn(pathInfo) != 1) {
      String errorMsg = String.format("Missing escaper :(."
          + "Got %d, expected 1", CharMatcher.is('/').countIn(pathInfo));
      Responses.sendError(response, errorMsg, 400);
      return;
    }

    String template;
    try {
      template = Templates.getTemplate(path[1] + ".tmpl", getClass());
    } catch (IOException e) {
      logger.fine(e.toString());
      Responses.sendError(response, e.getMessage(), 400);
      return;
    }

    if (path[0].equals("escapeHtml")) {
      Responses.sendXssed(response, Templates.replacePayload(template, htmlEscape(echoedParam)));
    } else if (path[0].equals("encodeUrl")) {
      Responses.sendXssed(response, Templates.replacePayload(template, encodeURL(echoedParam)));
    } else {
      Responses.sendError(response, "Unrecognized escaper", 400);
    }
  }
}
