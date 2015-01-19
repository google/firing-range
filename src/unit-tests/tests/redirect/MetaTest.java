package com.google.testing.security.firingrange.tests.redirect;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests for {@link Meta}.
 */
@RunWith(JUnit4.class)
public class MetaTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Test
  public void errorsOnEmptyUrl() throws IOException {
    when(request.getParameter(Meta.ECHOED_PARAM)).thenReturn(null);
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    new Meta().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void errorsOnBadUrl() throws IOException {
    when(request.getParameter(Meta.ECHOED_PARAM)).thenReturn("fo>:bar");
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
    new Meta().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void sendsRedirectOnParameter() throws IOException {
    String urlValue = "https://google.com";
    when(request.getParameter(Meta.ECHOED_PARAM)).thenReturn(urlValue);
    StringWriter strWriter = new StringWriter();
    PrintWriter printer = new PrintWriter(strWriter);
    when(response.getWriter()).thenReturn(printer);
    new Meta().doGet(request, response);
    verify(response).setStatus(200);
    assertTrue(strWriter.toString().contains("https://google.com"));
  }
}
