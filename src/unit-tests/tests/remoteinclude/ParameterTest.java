package com.google.testing.security.firingrange.tests.remoteinclude;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic tests for {@link Parameter}.
 */
@RunWith(JUnit4.class)
public class ParameterTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));
  }

  @Test
  public void failsOnInvalidType() throws IOException {
    when(request.getPathInfo()).thenReturn("/foobar");
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn("https://google.com");
   new Parameter().doGet(request, response);
   verify(response).setStatus(400);
  }

  @Test
  public void acceptsScriptUrl() throws IOException {
    when(request.getPathInfo()).thenReturn("/script");
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn("https://google.com");
    new Parameter().doGet(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void acceptsObjectType() throws IOException {
    when(request.getPathInfo()).thenReturn("/object/x-shockwave");
    when(request.getParameter(Parameter.ECHOED_PARAM)).thenReturn("https://google.com");
    new Parameter().doGet(request, response);
    verify(response).setStatus(200);
  }
}
