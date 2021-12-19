package org.wso2.carbon.identity.application.authenticator.custom.oidc.internal;

import org.wso2.carbon.identity.application.authenticator.custom.oidc.CustomOpenIDConnectAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
        name = "identity.application.authenticator.custom.oidc.component",
        immediate = true
)
public class CustomOpenIDConnectAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CustomOpenIDConnectAuthenticator customopenIDConnectAuthenticator = new CustomOpenIDConnectAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    customopenIDConnectAuthenticator, null);
            log.info(" Custom OpenID Connect Authenticator bundle is activated.");
        } catch (Throwable e) {
            String errMsg = "Error while activating Custom OIDC Authenticator.";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Custom OpenID Connect Authenticator bundle is deactivated.");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        CustomOpenIDConnectAuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service.");
        }
        CustomOpenIDConnectAuthenticatorDataHolder.getInstance().setRealmService(null);
    }

}
