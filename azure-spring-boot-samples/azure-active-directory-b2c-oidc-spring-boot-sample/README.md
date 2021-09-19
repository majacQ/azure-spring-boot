## How to configure

### Create your Azure Active Directory B2C tenant

Follow the guide of [AAD B2C tenant creation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-tenant).

### Register your Azure Active Directory B2C application

Follow the guide of [AAD B2C application registry](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-register-applications).
Please make sure that your b2c application `reply URL` contains `http://localhost:8080/home`.

### Create user flows

  <<<<<<< release/2.3.2
Follow the guide of [AAD B2C user flows creation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-user-flows).

### Configure the sample

#### Application.yml

1. Fill in `${your-tenant-name}` from Azure AD B2C portal `Overviews` domain name (format may looks like
`${your-tenant-name}.onmicrosoft.com`).
2. Select one registered instance under `Applications` from portal, and then:
    1. Fill in `${your-client-id}` from `Application ID`.
    2. Fill in `${your-client-secret}` from one of `Keys`.
3. Select `User flows`, and then:
    1. Fill in the `${your-sign-up-or-in-user-flow}` with the name of `sign-in-or-up` user flow.
    2. Fill in the `${your-profile-edit-user-flow}` with the name of `profile-edit` user flow.
    3. Fill in the `${your-password-reset-user-flow}` with the name of `password-reset` user flow.
4. Replace `${your-reply-url}` to `http://localhost:8080/home`.
5. Replace `${your-logout-success-url}` to `http://localhost:8080/login`.
  =======
Follow the guide of [AAD B2C user flows creation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-tutorials-web-app).

### Configure application.yml

1. Fill in `${your-tenant-name}` and `${your-client-id}` from Azure AD B2C portal `Applications`.
2. Fill in `${your-policy-name}` and `${your-policy-reply-url}` from the portal `User flows` for each policy.
3. Replace `${your-logout-success-url}` to `http://localhost:8080/`.
4. Replace `${your-url-to-process-password-reset}` to `http://localhost:8080/password-reset` if necessary.
5. Replace `${your-url-to-process-profile-edit}` to `http://localhost:8080/profile-edit` if necessary.
  >>>>>>> aad-b2c-integration

```yaml
azure:
  activedirectory:
    b2c:
      tenant: ${your-tenant-name}
  <<<<<<< release/2.3.2
      client-id: ${your-client-id}
      client-secret: ${your-client-secret}
      reply-url: ${your-reply-url} # should be absolute url.
      logout-success-url: ${your-logout-success-url}
      user-flows:
        sign-up-or-sign-in: ${your-sign-up-or-in-user-flow}
        profile-edit: ${your-profile-edit-user-flow}      # optional
        password-reset: ${your-password-reset-user-flow}  # optional
```

#### Templates greeting.html and home.html
1. Fill in the `${your-profile-edit-user-flow}` and `${your-password-reset-user-flow}` from the portal `User flows`.
Please make sure that these two placeholders should be the same as `application.yml` respectively.

  =======
      client-id: ${your-application-id}
      policies:
        sign-up-or-sign-in: # Required
          name: ${your-policy-name}
          reply-url: ${your-policy-reply-url}
        password-reset:     # Optional
          name: ${your-policy-name}
          reply-url: ${your-policy-reply-url}
        profile-edit:       # Optional
          name: ${your-policy-name}
          reply-url: ${your-policy-reply-url}

      # Only absolute URL is supported in following configuration
      logout-success-url: ${your-logout-success-url}            # Required
      password-reset-url: ${your-url-to-process-password-reset} # Optional
      profile-edit-url: ${your-url-to-process-profile-edit}     # Optional
```

  >>>>>>> aad-b2c-integration
### How to run

* Maven 

```
# Under azure-spring-boot project root directory
mvn clean install -DskipTests
cd azure-spring-boot-samples
cd azure-active-directory-b2c-oidc-spring-boot-sample
mvn spring-boot:run
```

### Validation
	
1. Access `http://localhost:8080/` as index page.
2. Sign up/in.
3. Access greeting button.
4. Logout.
5. Sign in.
6. Profile edit.
7. Password reset.
8. Logout
9. Sign in.

### FAQ

#### Sign in with loops to B2C endpoint ?
This issue almost due to polluted cookies of `localhost`. Clean up cookies of `localhost` and try it again.

#### More identity providers from AAD B2C login ?
Follow the guide of [Set up Google account with AAD B2C](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-setup-goog-app).
And also available for Amazon, Azure AD, FaceBook, Github, Linkedin and Twitter.
