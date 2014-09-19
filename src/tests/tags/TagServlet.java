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
 * A class only allowing a given set of tags and properties of those tags as its input payload.
 */
public class TagServlet extends HttpServlet {
  
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
    if (!(q.contains("body"))){
      elements.remove(body);
    }

    if (elements.isEmpty()) {
      Responses.sendError(response, "Invalid input, no tags", 400);
      return;
    }

    String allowedTag = "";
    String allowedAttribute = "";
    if (request.getPathInfo() != null) {
      String pathInfo = request.getPathInfo().substring(1);
      if (pathInfo.contains("/")) {
        allowedTag = pathInfo.split("/", 2)[0];
        allowedAttribute = pathInfo.split("/")[1];
      } else {
        allowedTag = pathInfo;
      }      
    }
    handleRequest(elements, response, allowedTag, allowedAttribute);
  }

  /**
   * Handles the request filtering out unallowed tags. Note that an empty allowedTag we allow
   * all tags.
   */
  private void handleRequest(
      Elements elements, HttpServletResponse response, String allowedTag, String allowedAttr)
          throws IOException {
    if (allowedTag.equalsIgnoreCase("script")) {
      elements.empty();
    }

    StringBuilder res = new StringBuilder();
    for (Element element : elements) {
      String tag = element.tagName();

      if (!allowedTag.isEmpty() && !allowedTag.equalsIgnoreCase(tag)) {
        continue;
      }

      if (!allowedAttr.isEmpty()) {
        Attributes attributes = element.attributes();
        for (Attribute attribute : attributes) {
          if (!attribute.getKey().equalsIgnoreCase(allowedAttr)) {
            Responses.sendError(response, "Invalid input attribute", 400);
            return;
          }
        }
      }
      res.append(element.toString());
    }
    Responses.sendXssed(response, res.toString());
  }
}
