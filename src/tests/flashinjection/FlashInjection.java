package com.google.testing.security.firingrange.tests.flashinjection;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The servlet returns JSON and handles two endpoints one of which echoes a query parameter in the
 * beginning of the request, and the other does not.
 */
public class FlashInjection extends HttpServlet {

  private static final String CALLBACK_IS_ECHOED_BACK = "callbackIsEchoedBack";

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String responseBody;
    String callback = request.getParameter("callback"); 
    if (request.getRequestURI().contains(CALLBACK_IS_ECHOED_BACK) && callback != null) {
      if (!Pattern.matches("^[a-zA-Z0-9]+$", callback)) {
        response.setStatus(500);
        return;
      }
      responseBody = callback + "({});";
    } else {
      responseBody = "func({});";
    }
    response.setContentType("application/json");
    response.setCharacterEncoding(UTF_8.name());
    response.setStatus(200);
    response.getWriter().write(responseBody);
    response.getWriter().flush();
  }
}
