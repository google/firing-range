package com.google.testing.security.firingrange.tests.cors;

import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This servlet generates a simple HTML page containing code that queries the same servlet
 * with an origin header. The response contains an Access-Control-Allow-Origin header
 * that is the same of the origin one.
 */
public class DynamicAllowOrigin extends HttpServlet {
  
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String baseUrl = request.getScheme() + "://" + request.getServerName(); 
    String template = Templates.getTemplate("origin_to_itself.tmpl", getClass());
    template = template.replace("$BASEURL$", baseUrl);
    Responses.sendNormalPage(response, template);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String origin = request.getHeader("Origin");
    if (origin != null) {
      response.setHeader("Access-Control-Allow-Origin", origin);
    }
    Responses.sendNormalPage(response, "Got it!");
  }
}
