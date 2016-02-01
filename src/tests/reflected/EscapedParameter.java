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

package com.google.testing.security.firingrange.tests.reflected;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Escaper;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Reflects a request parameter in the body, but performs escaping of some
 * characters before that.
 */
public class EscapedParameter extends HttpServlet {
  @VisibleForTesting static final String ECHOED_PARAM = "q";

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String template = Templates.getTemplate(request, getClass());
    Escaper.EscapeMode escaper =
        Escaper.EscapeMode.valueOf(Splitter.on('/').splitToList(request.getPathInfo()).get(2));
    String escapedParam = escaper.escape(echoedParam);
    Responses.sendXssed(response, Templates.replacePayload(template, escapedParam));
  }
}
