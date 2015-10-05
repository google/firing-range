package com.google.testing.security.firingrange.tests.reverseclickjacking;

import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
  public void returnsPageParameterInQueryInCallbackXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/InCallback/WithXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is set to DENY
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("callback=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInQueryOtherParameterXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/OtherParameter/WithXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is set to DENY
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("q=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInQueryInCallbackNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/InCallback/WithoutXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is NOT set to DENY
    verify(response, never()).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("callback=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInQueryOtherParameterNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/OtherParameter/WithoutXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is NOT set to DENY
    verify(response, never()).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that single and double quotes are stripped, while &#=_ are not
    verify(writer).write(contains("q=" + VULNERABLE_PARAMETER_STRIPPED));
  }

  @Test
  public void returnsPageParameterInFragmentInCallbackXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment/InCallback/WithXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is set to DENY
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that we return the right template
    verify(writer).write(contains("callback=' + q"));
  }

  @Test
  public void returnsPageParameterInFragmentOtherParameterXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment/OtherParameter/WithXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is set to DENY
    verify(response).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that we return the right template
    verify(writer).write(contains("q=' + q"));
  }

  @Test
  public void returnsPageParameterInFragmentInCallbackNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment/InCallback/WithoutXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is not set to DENY
    verify(response, never()).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that we return the right template
    verify(writer).write(contains("callback=' + q"));
  }

  @Test
  public void returnsPageParameterInFragmentOtherParameterNoXFO() throws IOException {
    when(request.getPathInfo())
        .thenReturn("multipage/ParameterInFragment/OtherParameter/WithoutXFO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(200);
    // Verify that the X_FRAME_OPTIONS header is not set to DENY
    verify(response, never()).setHeader(HttpHeaders.X_FRAME_OPTIONS, "DENY");
    // Verify that we return the right template
    verify(writer).write(contains("q=' + q"));
  }

  @Test
  public void returnsErrorOnInvalidParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/FOO");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnNoParameterLocation() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInQueryInCallbackInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/InCallback/INVALID");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInQueryOtherParamterInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery/OtherParameter/INVALID");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInQueryNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInQuery");
    when(request.getParameter(UniversalReverseClickjackingMultiPage.VULNERABLE_PARAMETER))
        .thenReturn(VULNERABLE_PARAMETER);
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInFragmentInCallbackInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment/InCallback/INVALID");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInFragmentOtherParameterInvalidXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment/OtherParameter/INVALID");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }

  @Test
  public void returnsErrorOnParameterInFragmentNoXFO() throws IOException {
    when(request.getPathInfo()).thenReturn("multipage/ParameterInFragment");
    new UniversalReverseClickjackingMultiPage().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we don't return a template
    verify(writer, never()).write(contains("<html>"));
  }
}
