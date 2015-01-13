package com.google.testing.security.firingrange.tests.reverseclickjacking;

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
 * Tests for {@link UniversalReverseClickjackingSinglePage}.
 */
@RunWith(JUnit4.class)
public class UniversalReverseClickjackingSinglePageTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(writer);
  }

  @Test
  public void returnsPageParameterInQuery() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/singlepage/ParameterInQuery");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
  }
  
  @Test
  public void returnsPageParameterInFragment() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/singlepage/ParameterInFragment");
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void returnsErrorOnInvalidParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/singlepage/FOO");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnNoParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/singlepage");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(400);
  }
}
