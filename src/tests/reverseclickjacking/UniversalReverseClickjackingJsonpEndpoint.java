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

import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A sample JSONP endpoint and test case for URC, where the value of a parameter in the request is
 * used as a callback function.
 */
public class UniversalReverseClickjackingJsonpEndpoint extends HttpServlet {
  static final String CALLBACK_REGEX = "[a-zA-Z0-9][a-zA-Z0-9\\._]*";
  static final String ECHOED_PARAM = "callback";
  static final int MAX_CALLBACK_LENGTH = 100;

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    if (!echoedParam.matches(CALLBACK_REGEX) || echoedParam.length() > MAX_CALLBACK_LENGTH) {
      Responses.sendError(response,
          "Invalid callback value: can only contain alphanumeric characters, dots and underscores.",
          400);
    } else {
      // Prefix the callback with /**/ to avoid Rosetta Flash-like attacks
      String json = "/**/" + echoedParam + "({'foobar':'foo'});";
      Responses.sendXssed(response, json, "application/json");
    }
  }
}
