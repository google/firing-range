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

  /** Ways to escape a plaintext string in HTML. */
  public enum EscapeMode {
    // foo="bar"
    DOUBLE_QUOTED_ATTRIBUTE,
    // foo='bar'
    SINGLE_QUOTED_ATTRIBUTE,
    // foo=bar
    UNQUOTED_ATTRIBUTE,
    // HTML
    HTML;

    public final String escape(String rawString) {
      switch(this) {
        case DOUBLE_QUOTED_ATTRIBUTE:
          return escapesDoubleQuotes(rawString);
        case SINGLE_QUOTED_ATTRIBUTE:
          return escapesSingleQuotes(rawString);
        case UNQUOTED_ATTRIBUTE:
          // Simply prevent closing the tag.
          return escapesGreatherThan(rawString);
        case HTML:
          return escapeHtml(rawString);
        default:
          throw new IllegalStateException("Unknown escaping mode");
      }
    }
  }

  private Escaper() {}

  /** HTML escapes double quotes. */
  public static String escapesDoubleQuotes(String rawString) {
    return rawString.replace("\"", "&quot;");
  }

  /** HTML escapes single quotes. */
  public static String escapesSingleQuotes(String rawString) {
    return rawString.replace("'", "&#39;");
  }

  /** HTML escapes > signs. */
  public static String escapesGreatherThan(String rawString) {
    return rawString.replace(">", "&gt;");
  }

  /**
   * Escapes HTML special chars inside a string by replacing the char with its HTML entities
   * representation.
   */
  public static String escapeHtml(String rawString) {
    return rawString.replace("'", "&#39;")
        .replace("\"", "&quot;")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }
}
