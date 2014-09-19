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
 
import com.google.testing.security.firingrange.utils.Responses;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A class only allowing tags, but filtering out event handlers. It only allows style as a property,
 * but explicitly blocks the word "expression" in the style. 
 */
public class Expression extends HttpServlet {
  
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    if (request.getParameter("q") == null) {
      Responses.sendError(response, "Missing q parameter", 400);
      return;
    }

    String  q = request.getParameter("q");
    Document doc = Jsoup.parseBodyFragment(q);
    Element body = doc.body();
    Elements elements = body.getAllElements();
    elements.remove(body);
    if (elements.isEmpty()) {
      Responses.sendError(response, "Invalid input, no tags", 400);
      return;
    }

    StringBuilder res = new StringBuilder();
    for (Element element : elements) {
      boolean validElement = true;

      Attributes attributes = element.attributes();
      for (Attribute attribute : attributes) {
        if (attribute.getKey().toLowerCase().startsWith("on")
            || attribute.getKey().toLowerCase().equals("href")
            || attribute.getKey().toLowerCase().equals("src")) {
          validElement = false;
        }

        if (attribute.getKey().toLowerCase().equals("style")
            && attribute.getValue().toLowerCase().contains("expression")) {
          validElement = false;
        }
      }

      if (validElement) {
        res.append(element.toString());
      }
    }
    Responses.sendXssed(response, res.toString());
  }
}
