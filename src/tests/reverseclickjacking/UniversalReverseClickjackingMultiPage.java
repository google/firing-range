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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.net.HttpHeaders;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;
import java.util.List;

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

  private enum ParameterLocation {
    ParameterInQuery("jsonly_in_query.tmpl"),
    ParameterInFragment("jsonly_in_fragment.tmpl");

    String template;

    ParameterLocation(String templatePath) {
      template = templatePath;
    }

    String getTemplate() throws IOException {
      return Templates.getTemplate(template, UniversalReverseClickjackingMultiPage.class);
    }
  }

  private enum ParameterSink {
    InCallback,
    OtherParameter
  }

  private enum HeaderOptions {
    WithXFO("DENY"),
    WithoutXFO("ALLOWALL");

    String directive;

    HeaderOptions(String xfoDirective) {
      directive = xfoDirective;
    }

    // Send the appropriate X-Frame-Options header
    void sendXfoHeader(HttpServletResponse response) {
      response.setHeader(HttpHeaders.X_FRAME_OPTIONS, directive);
    }
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Get parameters in the path
    List<String> parameters = Splitter.on('/').splitToList(request.getPathInfo());

    if (parameters.size() < 3) {
      Responses.sendError(
          response,
          "Please specify the location of the vulnerable parameter, its sink and the preference "
          + "for the X-Frame-Option header. For example: "
          + "/multipage/ParameterInQuery/InCallback/WithoutXFO/"
          + "?" + VULNERABLE_PARAMETER + "=x",
          400);
      return;
    }

    String template;
    ParameterLocation parameterLocation;
    ParameterSink parameterSink;
    try {
      parameterLocation = ParameterLocation.valueOf(parameters.get(1));
      parameterSink = ParameterSink.valueOf(parameters.get(2));
      HeaderOptions.valueOf(parameters.get(3)).sendXfoHeader(response);
      template = parameterLocation.getTemplate();
    } catch (IllegalArgumentException e) {
      Responses.sendError(
          response,
          "Invalid location of the vulnerable parameter, invalid sink or preference for the "
          + "X-Frame-Option header. For example: /multipage/ParameterInQuery/InCallback/WithoutXFO/"
          + "?" + VULNERABLE_PARAMETER + "=x",
          400);
      return;
    } catch (IOException e) {
      Responses.sendError(response, "Unable to load template.", 400);
      return;
    }

    String vulnerableParameter = Strings.nullToEmpty(request.getParameter(VULNERABLE_PARAMETER));
    // Strip quotes to "prevent" traditional XSS, but be vulnerable to parameter pollution
    vulnerableParameter = vulnerableParameter.replace("\"", "").replace("'", "");

    switch (parameterLocation) {
      case ParameterInQuery:
        switch (parameterSink) {
          case InCallback:
            // Reflect the user-provided parameter directly in the callback
            template = template.replace("%%CALLBACK%%", vulnerableParameter);
            // Leave the "other parameter" empty
            template = template.replace("%%OTHER_PARAMETER%%", "");
            break;
          case OtherParameter:
            // Use a generic callback
            template = template.replace("%%CALLBACK%%", "callbackFunc");
            // Reflect user-provided parameter directly in the "other parameter"
            template = template.replace("%%OTHER_PARAMETER%%", vulnerableParameter);
        }
        break;
      case ParameterInFragment:
        switch (parameterSink) {
          case InCallback:
            // Reflect the user-provided parameter directly in the callback
            template = template.replace("%%CALLBACK%%", "' + q + '");
            break;
          case OtherParameter:
            // Use a generic callback
            template = template.replace("%%CALLBACK%%", "callbackFunc");
        }
    }

    Responses.sendXssed(response, template);
  }
}
