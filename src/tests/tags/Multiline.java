/*
 *Copyright 2014 Google Inc. All rights reserved.
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

package com.google.testing.security.firingrange.tests.tags;
 
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This servlet will filter any tag but will be pierced by multiline requests.
 * Sample Payload: \r\n\r\n<script>alert(/1/)</script>
 */
public class Multiline extends HttpServlet {
  private static final Pattern TAG_FILTER = Pattern.compile("^.*<.*>.*$");
  
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String query = Strings.nullToEmpty(request.getParameter("q"));
    Matcher matcher = TAG_FILTER.matcher(query);
    if (matcher.matches()) {
      String error = "Invalid input, contains tags.";
      response.sendError(400, error);
      return;
    }
    String body = String.format("<html><body>%s</body></html>", query);
    Responses.sendXssed(response, body);
  }
}
