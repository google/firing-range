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

package com.google.testing.security.firingrange.tests.address;

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles address based DOM XSS, through various sources and sinks.
 */
public class Address extends HttpServlet {
  private static final String BASE_TEMPLATE = "address.tmpl";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String pathInfo = Strings.isNullOrEmpty(request.getPathInfo()) ? ""
       : request.getPathInfo().substring(1);
    
    if (CharMatcher.is('/').countIn(pathInfo) != 1) {
      String errorMsg = String.format("Missing sink, not enough sinks or too many sinks :(."
          + "Got %d, expected 1", CharMatcher.is('/').countIn(pathInfo));
      Responses.sendError(response, errorMsg, 400);
    } else {
      try {
        String[] pathInfoParts = pathInfo.split("/");
        
        if (pathInfoParts.length == 2) {
          Responses.sendXssed(response, generateTemplate(
              pathInfoParts[0], pathInfoParts[1]));
        } else {
          Responses.sendError(response, "Malformed URL", 400);
        }
      } catch (IllegalArgumentException | IOException e) {
        Responses.sendError(response, e.getMessage(), 400);
      }
    }
  }

  private String generateTemplate(String source, String sink) throws IOException {
    String sourcePath = "sources/" + source + ".tmpl";
    String sourceTemplate = Templates.getTemplate(sourcePath, Address.class);
    String sinkPath = "sinks/" + sink + ".tmpl";
    String sinkTemplate = Templates.getTemplate(sinkPath, Address.class);
  
    String baseTemplate = Templates.getTemplate(BASE_TEMPLATE, Address.class);
    return Templates.replacePayload(baseTemplate, sourceTemplate + sinkTemplate);
  }
}
