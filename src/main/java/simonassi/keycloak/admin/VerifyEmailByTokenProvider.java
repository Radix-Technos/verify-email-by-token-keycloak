package simonassi.keycloak.admin;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class VerifyEmailByTokenProvider implements AdminRealmResourceProvider {

    private final KeycloakSession session;

    public VerifyEmailByTokenProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void close() { }

    @Override
    public Object getResource(KeycloakSession keycloakSession, RealmModel realmModel, AdminPermissionEvaluator adminPermissionEvaluator, AdminEventBuilder adminEventBuilder) {
        return new VerifyEmailByTokenResource(session);
    }
}
