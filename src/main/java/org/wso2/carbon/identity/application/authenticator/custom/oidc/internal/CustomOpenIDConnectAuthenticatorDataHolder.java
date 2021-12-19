package org.wso2.carbon.identity.application.authenticator.custom.oidc.internal;

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.user.core.service.RealmService;

public class CustomOpenIDConnectAuthenticatorDataHolder {

    private static CustomOpenIDConnectAuthenticatorDataHolder instance =
            new CustomOpenIDConnectAuthenticatorDataHolder();

    private RealmService realmService;

    private ClaimMetadataManagementService claimMetadataManagementService;

    private CustomOpenIDConnectAuthenticatorDataHolder() {}

    public static CustomOpenIDConnectAuthenticatorDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {
        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        this.claimMetadataManagementService = claimMetadataManagementService;
    }
}
