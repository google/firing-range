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

import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Requests;
import javax.servlet.http.HttpServletRequest;

/**
 * Servlet that doesn't reflect arbitrary origins in the {@code Access-Control-Allow-Origin} header
 * but allows setting an HTTP scheme on an HTTPS resource.
 */
public final class AllowInsecureScheme extends AllowOriginServlet {
  @Override
  protected String getAllowOriginValue(HttpServletRequest request) {
    String origin = Strings.nullToEmpty(request.getHeader("Origin"));
    String scheme = origin.startsWith("http:") ? "http" : "https";
    String baseUrl = Requests.getBaseUrl(request);
    return scheme + baseUrl.substring(baseUrl.indexOf(":"));
  }
}
