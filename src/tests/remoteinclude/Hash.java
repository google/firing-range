package com.google.testing.security.firingrange.tests.remoteinclude;

import com.google.testing.security.firingrange.utils.Responses;
import com.google.testing.security.firingrange.utils.Templates;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles remote inclusion XSS due to hash parsing.
 */
public class Hash extends HttpServlet {
  private static final String BASE_TEMPLATE = "hash.tmpl";
  
  @Override
  public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String baseTemplate = Templates.getTemplate(BASE_TEMPLATE, getClass());
    Responses.sendXssed(response, baseTemplate);
  }
}
