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

package com.google.testing.security.firingrange.tests.reverseclickjacking;

import static com.google.common.net.UrlEscapers.urlFormParameterEscaper;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.net.HttpHeaders;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A test case for URC generating an HTML page with vulnerable Javascript code and no actionable
 * object (such as a button).
 */
public class UniversalReverseClickjackingMultiPage extends HttpServlet {
  @VisibleForTesting
  static final String VULNERABLE_PARAMETER = "q";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String headerOptions, parameterLocation, template;

    try {
      parameterLocation = Splitter.on('/').splitToList(request.getPathInfo()).get(2);
      headerOptions = Splitter.on('/').splitToList(request.getPathInfo()).get(3);
    } catch (IndexOutOfBoundsException e) {
      // Either the parameter location or the X-Frame-Options is not set.
      Responses.sendError(response,
          "Please specify the location of the vulnerable parameter and the preference for the"
          + " X-Frame-Option header.", 400);
      return;
    }

    String vulnerableParameter = Strings.nullToEmpty(request.getParameter(VULNERABLE_PARAMETER));
    // Encode URL to prevent XSS
    vulnerableParameter = urlFormParameterEscaper().escape(vulnerableParameter);

    switch (parameterLocation) {
      case "ParameterInQuery":
        template = Templates.getTemplate("jsonly_in_query.tmpl", getClass());
        template = Templates.replacePayload(template, vulnerableParameter);
        break;
      case "ParameterInFragment":
        template = Templates.getTemplate("jsonly_in_fragment.tmpl", getClass());
        break;
      default:
        Responses.sendError(response, "Invalid location of the vulnerable parameter.", 400);
        return;
    }

    switch (headerOptions) {
      case "WithXFO":
        response.setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
        break;
      case "WithoutXFO":
        break;
      default:
        Responses.sendError(response, "Invalid preference for the X-Frame-Option header.", 400);
        return;
    }

    Responses.sendXssed(response, template);
  }
}
