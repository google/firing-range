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
