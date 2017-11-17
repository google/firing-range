/*
 * Copyright 2017 Google Inc. All rights reserved.
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
package com.google.testing.security.firingrange.tests.cors;

import com.google.testing.security.firingrange.utils.Escaper;
import com.google.testing.security.firingrange.utils.Requests;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Abstract servlet that reacts with some kind of {@code Access-Control-Allow-Origin} header value
 * to a request with an {@code Origin} header.
 */
abstract class AllowOriginServlet extends HttpServlet {
  /**
   * Returns a value for the {@code Access-Control-Allow-Origin} header based on the request.
   */
  protected abstract String getAllowOriginValue(HttpServletRequest request);

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String template = Templates.getTemplate("origin_to_itself.tmpl", getClass());
    String url = Requests.getBaseUrl(request) + request.getRequestURI();
    template = template.replace("$URL$", Escaper.escapeHtml(url));
    Responses.sendNormalPage(response, template);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String origin = request.getHeader("Origin");
    if (origin != null) {
      response.setHeader("Access-Control-Allow-Origin", getAllowOriginValue(request));
      response.setHeader("Access-Control-Allow-Credentials", "true");
    }
    Responses.sendNormalPage(response, "Got it!");
  }

  private String getOwnPath(HttpServletRequest request) {
    return "foo";
  }
}
