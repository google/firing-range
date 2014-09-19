package com.google.testing.security.firingrange.tests.escape;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles reflected XSS with the payload escaped in JavaScript.
 */
public class JsEscape extends HttpServlet {

  @VisibleForTesting
  static final String ECHOED_PARAM = "q";

  private String stringEscape(String value) {
    return value.replace("\\", "\\\\")
        .replace("'", "\\'");
  }

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String template = Templates.getTemplate(request, getClass());
    Responses.sendXssed(response, Templates.replacePayload(template, stringEscape(echoedParam)));
  }
}
