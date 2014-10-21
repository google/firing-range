package com.google.testing.security.firingrange.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link Templates}.
 */
@RunWith(JUnit4.class)
public class TemplatesTest {

  @Test
  public void canOpenErrorTemplate() {
    assertFalse(Templates.errorTemplate().isEmpty());
  }

  @Test
  public void replacesPayload() {
    String template = "<faketemplate>" + Templates.PAYLOAD_PLACEHOLDER + "</faketemplate>";
    String testPayload = "testPayload";
    String expectedTemplate = "<faketemplate>" + testPayload + "</faketemplate>";
    assertEquals(expectedTemplate, Templates.replacePayload(template, testPayload));
  }
}
