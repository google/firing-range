package com.google.testing.security.firingrange.tests.reverseclickjacking;

import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
  private static final String VULNERABLE_PARAMETER = "FOO'\"&#=_FOO";
  private static final String VULNERABLE_PARAMETER_STRIPPED = "FOO&#=_FOO";

  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(writer);
  }

  @Test
  public void returnsPageParameterInQueryInCallback() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage/ParameterInQuery/InCallback");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("callback=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInQueryOtherParameter() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage/ParameterInQuery/OtherParameter");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("q=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInFragmentInCallback() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage/ParameterInFragment/InCallback");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that we return the right template, with the parameter reflected correctly
    verify(writer).write(contains("callback=' + q"));
  }

  @Test
  public void returnsPageParameterInFragmentOtherParameter() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage/ParameterInFragment/OtherParameter");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that we return the right template, with the parameter reflected correctly
    verify(writer).write(contains("q=' + q"));
  }

  @Test
  public void returnsErrorOnInvalidParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage/INVALID");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnNoParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("singlepage");
    when(request.getParameter(UniversalReverseClickjackingSinglePage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingSinglePage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }
}
