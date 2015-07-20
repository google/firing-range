package com.google.testing.security.firingrange.tests.reflected;

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
 * Tests for {@link Parameter}.
 */
@RunWith(JUnit4.class)
public class ParameterTest {
  private Parameter servlet = new Parameter();
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(mock(PrintWriter.class));    
  }

  @Test
  public void returnsOkByDefault() throws IOException {
    when(request.getPathInfo()).thenReturn("/body");
    servlet.service(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void returnsCustomStatus() throws IOException {
    when(request.getPathInfo()).thenReturn("/body/403");
    servlet.service(request, response);
    verify(response).setStatus(403);
  }
}
