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

import javax.servlet.http.HttpServletRequest;

/**
 * Utilities for handling HTTP requests.
 */
public final class Requests {
  /** Prevents instantiation. */
  private Requests() {}

  /**
   * Gets the base URL of the servlet.
   */
  public static String getBaseUrl(HttpServletRequest request) {
    String base = request.getScheme() + "://" + request.getServerName();
    if (request.getServerPort() == -1
        || (request.getServerPort() == 80 && request.getScheme().equals("http"))
        || (request.getServerPort() == 443 && request.getScheme().equals("https"))) {
      return base;
    }
    return base + ":" + request.getServerPort();
  }
}
