package com.google.testing.security.firingrange.tests.remoteinclude;

import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles remote inclusion XSS on parameters.
 */
public class Parameter extends HttpServlet {
  private static final String ECHOED_PARAM = "q";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    if (!echoedParam.startsWith("http")) {
      Responses.sendError(response, "Invalid URL", 400);
    } else {
      String template = Templates.getTemplate(request, getClass());
      Responses.sendXssed(response, Templates.replacePayload(template, echoedParam));
    }
  }
}
