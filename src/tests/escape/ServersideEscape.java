package com.google.testing.security.firingrange.tests.escape;

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles reflected XSS with serverside escaping of the payload.
 */
public class ServersideEscape extends HttpServlet {
  private static final String ECHOED_PARAM = "q";

  private String htmlEscape(String value) {
    return value.replace("<", "&lt;")
        .replace("&", "&amp;")
        .replace(">", "&gt;");
  }

  private String encodeURL(String value) {
    try {
      return URLEncoder.encode(value, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      return null;
    }
  }

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String echoedParam = Strings.nullToEmpty(request.getParameter(ECHOED_PARAM));
    String pathInfo = request.getPathInfo().substring(1);
    String[] path = pathInfo.split("/");

    if (CharMatcher.is('/').countIn(pathInfo) != 1) {
      String errorMsg = String.format("Missing escaper :(."
          + "Got %d, expected 1", CharMatcher.is('/').countIn(pathInfo));
      Responses.sendError(response, errorMsg, 400);
      return;
    }

    String template = Templates.getTemplate(path[1] + ".tmpl", getClass());
    if (path[0].equals("escapeHtml")) {
      Responses.sendXssed(response, Templates.replacePayload(template, htmlEscape(echoedParam)));
    } else if (path[0].equals("encodeUrl")) {
      Responses.sendXssed(response, Templates.replacePayload(template, encodeURL(echoedParam)));
    } else {
      Responses.sendError(response, "Unrecognized escaper", 400);
    }
  }
}
