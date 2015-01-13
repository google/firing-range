package com.google.testing.security.firingrange.tests.reverseclickjacking;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests for {@link UniversalReverseClickjackingMultiPage}.
 */
@RunWith(JUnit4.class)
public class UniversalReverseClickjackingMultiPageTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(writer);
  }

  @Test
  public void returnsPageParameterInQueryXFO() throws IOException {
    when(request.getPathInfo()).thenReturn(
        "reverseclickjacking/multipage/ParameterInQuery/WithXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
  }

  @Test
  public void returnsPageParameterInQueryNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn(
        "reverseclickjacking/multipage/ParameterInQuery/WithoutXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void returnsPageParameterInFragmentXFO() throws IOException {
    when(request.getPathInfo()).thenReturn(
        "reverseclickjacking/multipage/ParameterInFragment/WithXFO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
  }

  @Test
  public void returnsPageParameterInFragmentNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn(
        "reverseclickjacking/multipage/ParameterInFragment/WithoutXFO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
  }

  @Test
  public void returnsErrorOnInvalidParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage/FOO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnNoParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnParameterInQueryInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage/ParameterInQuery/FOO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnParameterInQueryNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage/ParameterInQuery");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn("FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnParameterInFragmentInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage/ParameterInFragment/FOO");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }

  @Test
  public void returnsErrorOnParameterInFragmentNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("reverseclickjacking/multipage/ParameterInFragment");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
  }
}
