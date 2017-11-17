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
package com.google.testing.security.firingrange.tests.angular;

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A servlet for providing a set of AngularJS-based XSS vulnerabilities.
 */
public class Angular extends HttpServlet {
  private static final String VERSION_PLACEHOLDER = "%%VERSION%%";
  private static final String ECHOED_PARAM = "q";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String pathInfo = request.getPathInfo().substring(1);

    if (CharMatcher.is('/').countIn(pathInfo) == 1) {
      String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));

      if (containsChars(echoedParam, '<', '>')) {
        Responses.sendError(response, "Invalid param.", 400);
        return;
      }


      String template;
      try {
        template = generateTemplate(
            pathInfo.split("/")[0], pathInfo.split("/")[1], echoedParam);
      } catch (IOException e) {
        Responses.sendError(response, "Invalid template request.", 400);
        return;
      } catch (IllegalArgumentException e) {
        Responses.sendError(response, e.getMessage(), 400);
        return;
      }

      Responses.sendXssed(response, template);
    } else {
      String errorMsg = String.format("Expecting exactly two parameters, got %d",
          CharMatcher.is('/').countIn(pathInfo));
      Responses.sendError(response, errorMsg, 400);
    }
  }

  private String generateTemplate(String template, String version, String payload)
      throws IOException, IllegalArgumentException {
    String sourcePath = template + ".tmpl";
    String angularTemplate = Templates.getTemplate(sourcePath, Angular.class);

    Pattern p = Pattern.compile("\\d+\\.\\d+\\.\\d+");
    if (!p.matcher(version).matches()) {
      throw new IllegalArgumentException("Invalid version!");
    }

    angularTemplate = angularTemplate.replace(VERSION_PLACEHOLDER, version);
    payload = processPayload(template, payload);

    return Templates.replacePayload(angularTemplate, payload);
  }

  private boolean containsChars(String echoedParam, Character... chars) {
    for (Character character : chars) {
      if (echoedParam.contains(character.toString())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Performs template-specific processing on the payload, in order to mimic parameter filtering or
   * escaping that the developer may have implemented.
   */
  private String processPayload(String template, String payload) {
    switch (template) {
      case "angular_body_raw_escaped":
        return payload.replace("{", "\\{").replace("}", "\\}");
      case "angular_body_raw_escaped_alt_symbols":
        return payload.replace("[", "\\[").replace("]", "\\]");
      default:
        return payload.replace("\"", "");
    }
  }
}
