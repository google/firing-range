package com.google.testing.security.firingrange.tests.reverseclickjacking;

import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
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
 * Tests for {@link UniversalReverseClickjackingJsonpEndpoint}.
 */
@RunWith(JUnit4.class)
public class UniversalReverseClickjackingJsonpEndpointTest {
  private HttpServletRequest request = mock(HttpServletRequest.class);
  private HttpServletResponse response = mock(HttpServletResponse.class);
  private PrintWriter writer = mock(PrintWriter.class);

  @Before
  public void setUpMocks() throws IOException {
    when(response.getWriter()).thenReturn(writer);
  }

  @Test
  public void returnsCallback() throws IOException {
    when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
        .thenReturn("FOO");
    new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    verify(response).setStatus(200);
    verify(response).setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
    verify(writer).write("/**/FOO({'foobar':'foo'});");
  }

  @Test
  public void refusesXssInjection() throws IOException {
    when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
        .thenReturn("<foo>");
    new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we also don't write broken callbacks
    verify(writer, never()).write(contains("/**/<foo>("));
  }

  @Test
  public void refusesEmptyCallback() throws IOException {
    when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
        .thenReturn("");
    new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we also don't write broken callbacks
    verify(writer, never()).write(contains("/**/("));
  }

  @Test
  public void checksCallbackLength() throws IOException {
    String callback =
        Strings.repeat("a", UniversalReverseClickjackingJsonpEndpoint.MAX_CALLBACK_LENGTH);

    when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
        .thenReturn(callback);
    new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    verify(response).setStatus(200);
    verify(response).setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
    verify(writer).write("/**/" + callback + "({'foobar':'foo'});");

    when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
        .thenReturn(callback + "a");
    new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    verify(response).setStatus(400);
    // Verify that we also don't write overlong callbacks
    verify(writer, never()).write(contains("/**/" + callback + "a("));
  }

  @Test
  public void checksCallbackRegex() throws IOException {
    ImmutableSet<String> invalidCallbacks =
        ImmutableSet.of(".", "-", "_", ".invalid", "-invalid", "_invalid");

    for (String callback : invalidCallbacks) {
      when(request.getParameter(UniversalReverseClickjackingJsonpEndpoint.ECHOED_PARAM))
          .thenReturn(callback);
      new UniversalReverseClickjackingJsonpEndpoint().doGet(request, response);
    }

    verify(response, times(invalidCallbacks.size())).setStatus(400);
    // Verify that we also don't write invalid callbacks
    verify(writer, never()).write(contains("/**/"));
  }
}
