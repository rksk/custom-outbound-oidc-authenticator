package org.wso2.carbon.identity.application.authenticator.custom.oidc;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.custom.oidc.internal.CustomOpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524019L;
    private static final String ACCESS_TOKEN_REQUIRED_IN_CLAIM = "accessTokenRequiredInClaim";
    private static final String ID_TOKEN_REQUIRED_IN_CLAIM = "idTokenRequiredInClaim";
    private static final String FED_ACCESS_TOKEN = "fedAccessToken";
    private static final String FED_ID_TOKEN = "fedIDToken";
    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        super.processAuthenticationResponse(request, response, context);

        if (Boolean.parseBoolean(context.getAuthenticatorProperties().get(ACCESS_TOKEN_REQUIRED_IN_CLAIM)) ||
                Boolean.parseBoolean((context.getAuthenticatorProperties().get(ID_TOKEN_REQUIRED_IN_CLAIM)))) {

            Map<String, Object> jsonObject = new HashMap<>();
            String accessToken = "";
            String idToken = "";

            if (Boolean.parseBoolean(context.getAuthenticatorProperties().get(ACCESS_TOKEN_REQUIRED_IN_CLAIM))) {
                accessToken = context.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN).toString();
                if (log.isDebugEnabled()) {
                    log.debug("accessToken retrieved from the federated authenticator:" + accessToken);
                }
                if (StringUtils.isNotBlank(accessToken)) {
                    jsonObject.put(FED_ACCESS_TOKEN, accessToken);
                }
            }

            if (Boolean.parseBoolean(context.getAuthenticatorProperties().get(ID_TOKEN_REQUIRED_IN_CLAIM)))  {
                idToken = context.getProperty(OIDCAuthenticatorConstants.ID_TOKEN).toString();
                if (log.isDebugEnabled()){
                    log.debug("idToken retrieved from the federated authenticator:" + idToken);
                }
                if (StringUtils.isNotBlank(idToken)) {
                    jsonObject.put(FED_ID_TOKEN, idToken);
                }
            }

            String attributeSeparator =
                    getMultiAttributeSeparator(context, context.getSubject().getAuthenticatedSubjectIdentifier());

            for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                buildClaimMappings(context.getSubject().getUserAttributes(), entry, attributeSeparator);
            }

            context.getSubject().setUserAttributes(context.getSubject().getUserAttributes());
        }

    }

    private String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {
            String tenantDomain = context.getTenantDomain();

            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = CustomOpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRealm userRealm = CustomOpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration()
                        .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (log.isDebugEnabled()) {
                    log.debug("For the claim mapping: " + attributeSeparator
                            + " is used as the attributeSeparator in tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while retrieving multi attribute separator",
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }
        return attributeSeparator;
    }

    @Override
    public String getFriendlyName() {
        return "Custom OpenID Connect";
    }

    @Override
    public String getName() {
        return "CustomOpenIDConnectAuthenticator";
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Custom OIDC client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Custom OIDC client secret value");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property authorizationEndpointUrl = new Property();
        authorizationEndpointUrl.setDisplayName("Authorization Endpoint URL");
        authorizationEndpointUrl.setRequired(true);
        authorizationEndpointUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_AUTHZ_URL);
        authorizationEndpointUrl.setDescription("Enter OAuth2/OpenID Connect authorization endpoint URL value");
        authorizationEndpointUrl.setDisplayOrder(3);
        configProperties.add(authorizationEndpointUrl);

        Property tokenEndpointUrl = new Property();
        tokenEndpointUrl.setDisplayName("Token Endpoint URL:");
        tokenEndpointUrl.setRequired(true);
        tokenEndpointUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_TOKEN_URL);
        tokenEndpointUrl.setDescription("Enter OAuth2/OpenID Connect token endpoint URL value");
        tokenEndpointUrl.setDisplayOrder(4);
        configProperties.add(tokenEndpointUrl);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url");
        callbackUrl.setDisplayOrder(5);
        configProperties.add(callbackUrl);

        Property userinfoEndpointUrl = new Property();
        userinfoEndpointUrl.setDisplayName("Userinfo Endpoint URL");
        userinfoEndpointUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_USER_INFO_EP_URL);
        userinfoEndpointUrl.setDescription("Enter value corresponding to userinfo endpoint url");
        userinfoEndpointUrl.setDisplayOrder(6);
        configProperties.add(userinfoEndpointUrl);

        Property oidcUserIDInClaims = new Property();
        oidcUserIDInClaims.setDisplayName("OpenID Connect User ID found in Claims");
        oidcUserIDInClaims.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS);
        oidcUserIDInClaims.setDescription("Specifies the location to find the user identifier in the " +
                "ID token assertion" + "\n" + "Ex: Set whether User ID found in 'sub' attribute OR among the claims." +
                "\n" + "By default we check for the User ID in 'sub' attribute, so the value is set as 'false'");
        oidcUserIDInClaims.setValue("false");
        oidcUserIDInClaims.setRequired(true);
        oidcUserIDInClaims.setDisplayOrder(7);
        configProperties.add(oidcUserIDInClaims);

        // Improve further with an option to select whether to include and Federated Identity Provider
        // Access Token and ID Token into the claims by setting Proper IdentityApplicationConstants
        // org/wso2/carbon/identity/application/common/util/IdentityApplicationConstants.java
        Property accessTokenRequired = new Property();
        accessTokenRequired.setDisplayName("Federated OIDC Access Token required in Claim");
        accessTokenRequired.setName(ACCESS_TOKEN_REQUIRED_IN_CLAIM);
        accessTokenRequired.setDescription("Specify whether the Federated OIDC Access Token is required to be " +
                "retrieved as a claim");
        accessTokenRequired.setValue("false");
        accessTokenRequired.setDefaultValue("false");
        accessTokenRequired.setDisplayOrder(8);
        configProperties.add(accessTokenRequired);

        Property idTokenRequired = new Property();
        idTokenRequired.setDisplayName("Federated OIDC ID Token required in Claim");
        idTokenRequired.setName(ID_TOKEN_REQUIRED_IN_CLAIM);
        idTokenRequired.setDescription("Specify whether the Federated OIDC ID Token is required to be " +
                "retrieved as a claim");
        idTokenRequired.setValue("false");
        idTokenRequired.setDefaultValue("false");
        idTokenRequired.setDisplayOrder(9);
        configProperties.add(idTokenRequired);

        Property scope = new Property();
        scope.setDisplayName("Additional Query Parameters");
        scope.setName("AdditionalQueryParameters");
//        scope.setValue("scope=openid email profile");
        scope.setDescription("Additional query parameters. e.g: paramName1=value1");
        scope.setDisplayOrder(10);
        configProperties.add(scope);

        Property isBasicAuthEnabled = new Property();
        isBasicAuthEnabled.setDisplayName("Enable HTTP basic auth for client authentication");
        isBasicAuthEnabled.setName(OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED);
        isBasicAuthEnabled.setValue("false");
        isBasicAuthEnabled.setDefaultValue("false");
        isBasicAuthEnabled.setDescription("Specifies that HTTP basic authentication should be used for client " +
                "authentication, else client credentials will be included in the request body ");
        isBasicAuthEnabled.setDisplayOrder(11);
        configProperties.add(isBasicAuthEnabled);

        return configProperties;
    }
}
