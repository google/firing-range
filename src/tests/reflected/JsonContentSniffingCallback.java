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

package com.google.testing.security.firingrange.tests.reflected;

import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles reflected XSS on JSON via content sniffing in a secret callback argument.
 */
public class JsonContentSniffingCallback extends HttpServlet {
  private static final String ECHOED_PARAM = "callback";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String json;
    if (echoedParam.isEmpty()) {
      json = "{'foobar':'foo'}";
    } else {
      json = echoedParam + "({'foobar':'foo'});";
    }
    Responses.sendXssed(response, json, "application/json");
  }
}
