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

package com.google.testing.security.firingrange.utils;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.io.Resources;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

/**
 * A helper class to manipulate templates.
 */
@Immutable
public final class Templates {
  private static final String ERROR_TEMPLATE = "data/error.tmpl";
  @VisibleForTesting
  static final String PAYLOAD_PLACEHOLDER = "%%PAYLOAD%%";
  private static final Logger logger = Logger.getLogger(Templates.class.getCanonicalName());

  private Templates() {}

  /**
   * Extract a template given an HTTP request. The last path component is the template.
   * @throws IOException if it cannot find the template.
   */
  public static String getTemplate(HttpServletRequest request, Class<? extends HttpServlet> clazz)
      throws IOException {
    String firstPathPart = Splitter.on('/').splitToList(request.getPathInfo()).get(1);
    String templateName = firstPathPart + ".tmpl";
    return getTemplate(templateName, clazz);
  }

  /**
   * Extracts a template given the path relative to a {@code clazz}.
   * @throws IOException if it cannot find the template.
   */
  public static String getTemplate(String relativePath, Class<? extends HttpServlet> clazz) 
      throws IOException {
    Preconditions.checkArgument(!relativePath.contains(".."));
    try {
      URL resource = Resources.getResource(clazz, "data/" + relativePath);
      return templateToString(resource);
    } catch (IllegalArgumentException e) {
      logger.info("Cannot find template for " + relativePath);
      throw new IOException(errorTemplate());
    }
  }

  @VisibleForTesting
  static String errorTemplate() {
    // Unable to find this template. Return error template.
    try {
      return templateToString(Resources.getResource(Templates.class, ERROR_TEMPLATE));
    } catch (IllegalArgumentException e2) {
      // Unable to find the error template!
      logger.severe("Cannot find error template");
      return "";
    }
  }

  private static String templateToString(URL resource) {
    try {
      return Resources.toString(resource, UTF_8);
    } catch (IOException e) {
      logger.severe("Cannot open template: " + resource);
      return "ERROR, cannot open template";
    }
  }

  /**
   * Sets the payload in a given template.
   */
  public static String replacePayload(String template, String payload) {
    return template.replace(PAYLOAD_PLACEHOLDER, payload);
  }
}
