/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.b2c;

  <<<<<<< release/2.3.2
import lombok.*;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import java.net.MalformedURLException;
  =======
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
  >>>>>>> aad-b2c-integration

@Getter
@Setter
@Validated
@NoArgsConstructor
@ConfigurationProperties(prefix = AADB2CProperties.PREFIX)
public class AADB2CProperties {

  <<<<<<< release/2.3.2
    private static final String USER_FLOWS = "user-flows";
  =======
    private static final String POLICIES = "policies";

    private static final String SIGN_UP_OR_SIGN_IN = "sign-up-or-sign-in";

    private static final String PASSWORD_RESET = "password-reset";

    private static final String PROFILE_EDIT = "profile-edit";

    private static final String POLICY_PASSWORD_RESET = POLICIES + "." + PASSWORD_RESET;

    private static final String POLICY_PROFILE_EDIT = POLICIES + "." + PROFILE_EDIT;
  >>>>>>> aad-b2c-integration

    /**
     * We do not use ${@link String#format(String, Object...)}
     * as it's not real constant, which cannot be referenced in annotation.
     */
  <<<<<<< release/2.3.2
    public static final String USER_FLOW_PASSWORD_RESET = USER_FLOWS + ".password-reset";

    public static final String USER_FLOW_PROFILE_EDIT = USER_FLOWS + ".profile-edit";

    public static final String USER_FLOW_SIGN_UP_OR_SIGN_IN = USER_FLOWS + ".sign-up-or-sign-in";

    public static final String DEFAULT_LOGOUT_SUCCESS_URL = "http://localhost:8080/login";

    public static final String PREFIX = "azure.activedirectory.b2c";
  =======
    private static final String POLICY_SIGN_UP_OR_SIGN_IN = POLICIES + "." + SIGN_UP_OR_SIGN_IN;

    public static final String PREFIX = "azure.activedirectory.b2c";

    public static final String POLICY_SIGN_UP_OR_SIGN_IN_NAME = POLICY_SIGN_UP_OR_SIGN_IN + ".name";

    public static final String POLICY_SIGN_UP_OR_SIGN_IN_REPLY_URL = POLICY_SIGN_UP_OR_SIGN_IN + ".reply-url";

    public static final String POLICY_PASSWORD_RESET_NAME = POLICY_PASSWORD_RESET + ".name";

    public static final String POLICY_PASSWORD_RESET_REPLY_URL = POLICY_PASSWORD_RESET + ".reply-url";

    public static final String POLICY_PROFILE_EDIT_NAME = POLICY_PROFILE_EDIT + ".name";

    public static final String POLICY_PROFILE_EDIT_REPLY_URL = POLICY_PROFILE_EDIT + ".reply-url";

    public static final String POLICY_PASSWORD_RESET_REDIRECT_URL = POLICY_PASSWORD_RESET + ".redirect-uri";

    public static final String PASSWORD_RESET_URL = "password-reset-url";

    public static final String LOGOUT_SUCCESS_URL = "logout-success-url";

    public static final String PROFILE_EDIT_URL = "profile-edit-url";

    public static final String SESSION_STATE_LESS = "session-stateless";
  >>>>>>> aad-b2c-integration

    /**
     * The name of the b2c tenant.
     */
    @NotBlank(message = "tenant name should not be blank")
    private String tenant;

    /**
  <<<<<<< release/2.3.2
     * Use OIDC ${@link OidcAuthorizationCodeAuthenticationProvider} by default. If set to false,
     * will use Oauth2 ${@link OAuth2AuthorizationCodeAuthenticationProvider}.
     */
    private Boolean oidcEnabled = true;

    /**
  =======
  >>>>>>> aad-b2c-integration
     * The application ID that registered under b2c tenant.
     */
    @NotBlank(message = "client ID should not be blank")
    private String clientId;

  <<<<<<< release/2.3.2
    /**
     * The application secret that registered under b2c tenant.
     */
    @NotBlank(message = "client secret should not be blank")
    private String clientSecret;

    @URL(message = "reply URL should be valid URL")
    private String replyUrl;

    @URL(message = "logout success should be valid URL")
    private String logoutSuccessUrl = DEFAULT_LOGOUT_SUCCESS_URL;

    /**
     * The all user flows which is created under b2c tenant.
     */
    private UserFlows userFlows = new UserFlows();
  =======
    @URL
    @Setter
    @JsonProperty(LOGOUT_SUCCESS_URL)
    private String logoutSuccessUrl;

    @Setter
    @JsonProperty(PASSWORD_RESET_URL)
    private String passwordResetUrl;

    @Setter
    @JsonProperty(PROFILE_EDIT_URL)
    private String profileEditUrl;

    /**
     * The all polices which is created under b2c tenant.
     */
    @JsonProperty(POLICIES)
    private Policies policies = new Policies();
  >>>>>>> aad-b2c-integration

    /**
     * Telemetry data will be collected if true, or disable data collection.
     */
    private boolean allowTelemetry = true;

  <<<<<<< release/2.3.2
    private String getReplyURLPath(@URL String replyURL) {
        try {
            return new java.net.URL(replyURL).getPath();
        } catch (MalformedURLException e) {
            throw new AADB2CConfigurationException("Failed to get path of given URL.", e);
        }
    }

    @NonNull
    public String getLoginProcessingUrl() {
        return getReplyURLPath(replyUrl);
  =======
    @Getter
    @Validated
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class Policies {

        /**
         * The sign-up-or-sign-in policy which is created under b2c tenant.
         */
        @JsonProperty(SIGN_UP_OR_SIGN_IN)
        private Policy signUpOrSignIn = new Policy();

        /**
         * The password-reset policy which is created under b2c tenant.
         */
        @JsonProperty(PASSWORD_RESET)
        private Policy passwordReset = new Policy();

        /**
         * The password-reset policy which is created under b2c tenant.
         */
        @JsonProperty(PROFILE_EDIT)
        private Policy profileEdit = new Policy();
        // TODO(pan): will add more policies like sign-in, sign-up, profile-editing and password-reset.
  >>>>>>> aad-b2c-integration
    }

    @Getter
    @Setter
    @Validated
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
  <<<<<<< release/2.3.2
    protected static class UserFlows {

        /**
         * The sign-up-or-sign-in user flow which is created under b2c tenant.
         */
        @NotBlank(message = "sign-up-or-in value should not be blank")
        private String signUpOrSignIn;

        /**
         * The profile-edit user flow which is created under b2c tenant.
         */
        private String profileEdit;

        /**
         * The password-reset user flow which is created under b2c tenant.
         */
        private String passwordReset;
  =======
    public static class Policy {

        /**
         * The name of policy which is created under b2c tenant.
         */
        @NotBlank(message = "policy name should not be blank")
        private String name;

        /**
         * The redirect URI which is configured under b2c tenant.
         */
        @URL(message = "reply URL should not be blank")
        private String replyURL;
  >>>>>>> aad-b2c-integration
    }
}
