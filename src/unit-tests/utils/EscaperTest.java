/*
 * Copyright 2016 Google Inc. All rights reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link Escaper}.
 */
@RunWith(JUnit4.class)
public class EscaperTest {

  @Test public void escapesQuotes() {
    String in = "foo\"";
    String out = Escaper.EscapeMode.DOUBLE_QUOTED_ATTRIBUTE.escape(in);
    assertNotEquals(in, out);
    assertFalse(out.contains("\""));
    
    in = "foo'";
    out = Escaper.EscapeMode.SINGLE_QUOTED_ATTRIBUTE.escape(in);
    assertNotEquals(in, out);
    assertFalse(out.contains("'"));
  }

  @Test public void escapesClosingTag() {
    assertEquals("<foo&gt;", Escaper.escapesGreatherThan("<foo>"));
  }

  
  @Test public void escapesHtml() {
    assertEquals("&lt;foo&gt;", Escaper.escapeHtml("<foo>"));
  }
}
