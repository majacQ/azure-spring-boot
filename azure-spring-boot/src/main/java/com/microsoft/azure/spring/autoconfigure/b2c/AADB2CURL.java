/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.b2c;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
  <<<<<<< release/2.3.2
import org.springframework.util.Assert;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
  =======
import lombok.NonNull;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
  >>>>>>> aad-b2c-integration

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AADB2CURL {

  <<<<<<< release/2.3.2
    private static final String AUTHORIZATION_URL_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/oauth2/v2.0/authorize";

    private static final String TOKEN_URL_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/oauth2/v2.0/token?p=%s";

    private static final String JWKSET_URL_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/discovery/v2.0/keys?p=%s";

    private static final String END_SESSION_URL_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/oauth2/v2.0/logout?post_logout_redirect_uri=%s&p=%s";

    public static String getAuthorizationUrl(String tenant) {
        Assert.hasText(tenant, "tenant should have text.");

        return String.format(AUTHORIZATION_URL_PATTERN, tenant, tenant);
    }

    public static String getTokenUrl(String tenant, String userFlow) {
        Assert.hasText(tenant, "tenant should have text.");
        Assert.hasText(userFlow, "user flow should have text.");

        return String.format(TOKEN_URL_PATTERN, tenant, tenant, userFlow);
    }

    public static String getJwkSetUrl(String tenant, String userFlow) {
        Assert.hasText(tenant, "tenant should have text.");
        Assert.hasText(userFlow, "user flow should have text.");

        return String.format(JWKSET_URL_PATTERN, tenant, tenant, userFlow);
    }

    public static String getEndSessionUrl(String tenant, String logoutUrl, String userFlow) {
        Assert.hasText(tenant, "tenant should have text.");
        Assert.hasText(logoutUrl, "logoutUrl should have text.");
        Assert.hasText(userFlow, "user flow should have text.");

        return String.format(END_SESSION_URL_PATTERN, tenant, tenant, getEncodedURL(logoutUrl), userFlow);
    }

    private static String getEncodedURL(String url) {
        Assert.hasText(url, "url should have text.");

  =======
    public static final String PARAMETER_CODE = "code";

    public static final String PARAMETER_ID_TOKEN = "id_token";

    public static final String PARAMETER_STATE = "state";

    public static final String PARAMETER_ERROR = "error";

    public static final String PARAMETER_ERROR_DESCRIPTION = "error_description";

    public static final String HEADER_AUTHENTICATION = "Authorization";

    // 'p' is the abbreviation for 'policy'.
    private static final String OPENID_AUTHORIZE_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/oauth2/v2.0/authorize?" +
                    "client_id=%s&" +
                    "redirect_uri=%s&" +
                    "response_mode=query&" +
                    "response_type=code+id_token&" +
                    "scope=openid&" +
                    "state=%s&" +
                    "nonce=%s&" +
                    "p=%s";

    private static final String OPENID_LOGOUT_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/oauth2/v2.0/logout?" +
                    "post_logout_redirect_uri=%s&" +
                    "p=%s";

    private static final String OPENID_CONFIGURATION_PATTERN =
            "https://%s.b2clogin.com/%s.onmicrosoft.com/v2.0/.well-known/openid-configuration?" +
                    "p=%s";

    private static final String STATE_REQUEST_URL = "request-url";

    private static final String STATE_PROPERTY_SEPARATOR = ":";

    public static final String ATTRIBUTE_NONCE = "nonce";

    public static final String ATTRIBUTE_STATE = "state";

    private static String getUUID() {
        return UUID.randomUUID().toString();
    }

    private static String getEncodedURL(@NonNull String url) {
  >>>>>>> aad-b2c-integration
        try {
            return URLEncoder.encode(url, "utf-8");
        } catch (UnsupportedEncodingException e) {
            throw new AADB2CConfigurationException("failed to encode url: " + url, e);
        }
    }
  <<<<<<< release/2.3.2
  =======

    public static String toAbsoluteURL(String url, @NonNull HttpServletRequest request) {
        try {
            new URL(url);
            return url;
        } catch (MalformedURLException e) {
            throw new AADB2CConfigurationException("Invalid URL: " + url, e);
// TODO(pan): need to investigate the relative URL with context path of spring security, only support absolute URL.
//            try {
//                new URI(url);
//                final URL requestURL = new URL(request.getRequestURL().toString());
//            URI format =>scheme:[//authority]path[?query][#fragment]
//                return String.format("%s:%s%s",
//                        requestURL.getProtocol(),
//                        StringUtils.hasText(requestURL.getAuthority()) ? "//" + requestURL.getAuthority() : "",
//                        url.startsWith("/") ? url : "/" + url
//                );
//            } catch (URISyntaxException | MalformedURLException e) {
//                throw new AADB2CConfigurationException("Invalid URL: " + url, e);
//            }
        }
    }

    public static String getStateRequestUrl(String state) throws AADB2CAuthenticationException {
        Assert.hasText(state, "state should contain text.");

        final List<String> stateProperties = Arrays.asList(state.split(STATE_PROPERTY_SEPARATOR));

        Assert.isTrue(stateProperties.size() > 1, "state properties should contain 2 or more elements.");
        Assert.isTrue(stateProperties.get(0).equals(STATE_REQUEST_URL), "property should be " + STATE_REQUEST_URL);

        final String requestURL = stateProperties.get(1);

        if (StringUtils.hasText(requestURL)) {
            final byte[] decodedURL = Base64.getDecoder().decode(requestURL.getBytes(StandardCharsets.UTF_8));
            return new String(decodedURL, StandardCharsets.UTF_8);
        }

        throw new AADB2CAuthenticationException("The reply state has unexpected content: " + state);
    }

    /**
     * Take state's format as '${@link AADB2CURL#STATE_REQUEST_URL}:RequestURL', the RequestURL
     * will be base64 encoded.
     *
     * @param requestURL from ${@link HttpServletRequest} that user attempt to access.
     * @return the encoded state String.
     */
    private static String getState(HttpServletRequest request, String requestURL) {
        final String url = toAbsoluteURL(requestURL, request);
        final String encodedURL = Base64.getEncoder().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        final String state = String.format("%s:%s", STATE_REQUEST_URL, encodedURL);

        request.getSession().setAttribute(ATTRIBUTE_STATE, state);

        return state;
    }

    private static String getNonce(HttpServletRequest request) {
        final String nonce = getUUID();

        request.getSession().setAttribute(ATTRIBUTE_NONCE, nonce);

        return nonce;
    }

    private static String getOpenIdAuthorizeURL(AADB2CProperties properties, AADB2CProperties.Policy policy,
                                                String redirectURL, HttpServletRequest request) {
        final String nonce = getNonce(request);
        final String state = getState(request, redirectURL);

        return String.format(OPENID_AUTHORIZE_PATTERN,
                properties.getTenant(),
                properties.getTenant(),
                properties.getClientId(),
                getEncodedURL(toAbsoluteURL(policy.getReplyURL(), request)),
                state,
                nonce,
                policy.getName()
        );
    }

    /**
     * Get the openid sign up or sign in URL based on ${@link AADB2CProperties}, within redirectURL in state field.
     *
     * @param properties  of ${@link AADB2CProperties}.
     * @param redirectURL from ${@link HttpServletRequest} that user attempt to access.
     * @return the URL of openid sign up or sign in.
     */
    public static String getOpenIdSignUpOrSignInURL(@NonNull AADB2CProperties properties, String redirectURL,
                                                    @NonNull HttpServletRequest request) {
        return getOpenIdAuthorizeURL(properties, properties.getPolicies().getSignUpOrSignIn(), redirectURL, request);
    }

    /**
     * Get the openid sign up or sign in URL based on ${@link AADB2CProperties}, within redirectURL in state field.
     *
     * @param properties  of ${@link AADB2CProperties}.
     * @param redirectURL from ${@link HttpServletRequest} that user attempt to access.
     * @param request     from ${@link HttpServletRequest}.
     * @return the URL of openid password reset.
     */
    public static String getOpenIdPasswordResetURL(@NonNull AADB2CProperties properties, String redirectURL,
                                                   @NonNull HttpServletRequest request) {
        return getOpenIdAuthorizeURL(properties, properties.getPolicies().getPasswordReset(), redirectURL, request);
    }

    /**
     * Get the openid profile edit URL based on ${@link AADB2CProperties}, within redirectURL in state field.
     *
     * @param properties  of ${@link AADB2CProperties}.
     * @param redirectURL from ${@link HttpServletRequest} that user attempt to access.
     * @param request     from ${@link HttpServletRequest}.
     * @return the URL of openid profile edit.
     */
    public static String getOpenIdProfileEditURL(@NonNull AADB2CProperties properties, String redirectURL,
                                                 @NonNull HttpServletRequest request) {
        return getOpenIdAuthorizeURL(properties, properties.getPolicies().getProfileEdit(), redirectURL, request);
    }

    /**
     * Get the openid logout URL based on ${@link AADB2CProperties}.
     *
     * @param properties of ${@link AADB2CProperties}.
     * @return the URL of openid logout.
     */
    public static String getOpenIdLogoutURL(@NonNull AADB2CProperties properties, @NonNull HttpServletRequest request) {
        return String.format(OPENID_LOGOUT_PATTERN,
                properties.getTenant(),
                properties.getTenant(),
                getEncodedURL(toAbsoluteURL(properties.getLogoutSuccessUrl(), request)),
                properties.getPolicies().getSignUpOrSignIn().getName()
        );
    }

    /**
     * Get the openid configuration URL based on ${@link AADB2CProperties}.
     *
     * @param properties of ${@link AADB2CProperties}.
     * @return the URL of openid configuration.
     */
    public static String getOpenIdSignUpOrInConfigurationURL(@NonNull AADB2CProperties properties) {
        return String.format(OPENID_CONFIGURATION_PATTERN,
                properties.getTenant(),
                properties.getTenant(),
                properties.getPolicies().getSignUpOrSignIn().getName()
        );
    }

    /**
     * Validate the error and description from reply url request.
     *
     * @param request of ${@link HttpServletRequest}.
     * @throws AADB2CAuthenticationException when there is error in reply url query.
     */
    public static void validateReplyRequest(@NonNull HttpServletRequest request) throws AADB2CAuthenticationException {
        final String code = request.getParameter(PARAMETER_ERROR);

        if (StringUtils.hasText(request.getParameter(PARAMETER_ERROR))) {
            final String description = request.getParameter(PARAMETER_ERROR_DESCRIPTION);
            final String message = String.format("%s:%s.", code, description);

            throw new AADB2CAuthenticationException("Authentication failure: " + message);
        }
    }
  >>>>>>> aad-b2c-integration
}
