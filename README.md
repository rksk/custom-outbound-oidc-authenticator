# Custom Outbound OpenID Connect Authenticator

This authenticator is an extended OIDC authenticator for [WSO2 Identity Server](https://wso2.com/identity-server/)
that allows sending the access and/or ID token of a OIDC federated identity provider to the client application.

## Steps to deploy

1. Clone the repository and build the project using maven.
2. Copy the `target/wso2-oidc-authenticator-1.0.0.jar` to the `<IS_HOME>/repository/components/dropins` directory of the WSO2 Identity Server.
3. Restart the Identity Server instance.
4. After successfully deploying the CustomOpenIDConnectAuthenticator you would be able to find it under the Identity Providers -> Federated Authenticators section.
5. Expand the `Custom OpenID Connect Configuration` and configure the required parameters to connect to the External Identity Provider.
6. We have introduced a new parameter that lets the user decide whether the Federated OIDC Access Token/ ID Token should be included in the User Claim. Make sure to configure the following parameters as per the requirement.
   - Federated OIDC Access Token required in Claim: true/false
   - Federated OIDC ID Token required in Claim: true/false
7. Add two local claims that will be used to refer to the federated OIDC Access Token and ID Token (the claim URI and mapped attributes can be selected as per your preference)
   - http://wso2.org/claims/fedAccessToken
   - http://wso2.org/claims/fedIDToken
8. Add two external claims under the `http://wso2.org/oidc/claim` dialect. (The OIDC Claim URIs should be these values as they are defined in the custom authenticator)
   - fedAccessToken -> http://wso2.org/claims/fedAccessToken
   - fedIDToken -> http://wso2.org/claims/fedIDToken
9. Add these two claims to the openid scope by going to List OIDC scopes page and clicking update for openid scope.
10. Add the above two local claims as requested claims for the relevant service provider.