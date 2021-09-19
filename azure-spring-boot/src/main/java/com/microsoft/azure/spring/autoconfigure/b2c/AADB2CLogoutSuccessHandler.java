/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.b2c;

import lombok.NonNull;
  <<<<<<< release/2.3.2
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
  =======
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

  >>>>>>> aad-b2c-integration
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

  <<<<<<< release/2.3.2
public class AADB2CLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final AADB2CProperties properties;

    public AADB2CLogoutSuccessHandler(@NonNull AADB2CProperties properties) {
        this.properties = properties;

        super.setDefaultTargetUrl(getAADB2CEndSessionUrl());
    }

    private String getAADB2CEndSessionUrl() {
        final String userFlow = properties.getUserFlows().getSignUpOrSignIn();
        final String logoutSuccessUrl = properties.getLogoutSuccessUrl();

        return AADB2CURL.getEndSessionUrl(properties.getTenant(), logoutSuccessUrl, userFlow);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        super.onLogoutSuccess(request, response, authentication);
    }
  =======
@Slf4j
public class AADB2CLogoutSuccessHandler implements LogoutSuccessHandler {

    private final AADB2CProperties b2cProperties;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public AADB2CLogoutSuccessHandler(@NonNull AADB2CProperties b2cProperties) {
        this.b2cProperties = b2cProperties;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        log.debug("Redirect to AAD B2C for invalidating token. After that AAD B2C will redirect to URL {}.",
                b2cProperties.getLogoutSuccessUrl());

        redirectStrategy.sendRedirect(request, response, AADB2CURL.getOpenIdLogoutURL(b2cProperties, request));
    }

  >>>>>>> aad-b2c-integration
}
