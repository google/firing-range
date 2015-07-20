/*
 * Copyright 2015 Google Inc. All rights reserved.
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

/**
 * This class provides some basic escaping functionality.
 */
public final class Escaper {

  /**
   * Escapes HTML special chars inside a string by replacing the char with its HTML entities
   * representation.
   * @param rawString The string to escape.
   * @return The escaped string.
   */
  public static String escapeHtml(String rawString) {
    return rawString.replace("'", "&#39;")
        .replace("\"", "&quot;")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }
}
