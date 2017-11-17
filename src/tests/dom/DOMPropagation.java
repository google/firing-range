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

package com.google.testing.security.firingrange.tests.dom;

import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DOMPropagation extends HttpServlet {

  private static final String TOXIC_TEMPLATE = "toxicdom.tmpl";
  private static final String DOM_PROPAGATION_TEMPLATE = "dompropagation.tmpl";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String toxicTemplate = Templates.getTemplate(TOXIC_TEMPLATE, getClass());
    String domPropagationTemplate = Templates.getTemplate(DOM_PROPAGATION_TEMPLATE, getClass());
    String template = Templates.replacePayload(toxicTemplate, domPropagationTemplate);

    Responses.sendXssed(response, template);
  }

}
