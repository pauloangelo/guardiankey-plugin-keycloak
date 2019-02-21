package io.guardiankey.keycloak;

import org.keycloak.Config.Scope;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class GuardianKeyEventListenerFactory implements EventListenerProviderFactory {

    private static final GuardianKeyAuthenticator SINGLETON = new GuardianKeyAuthenticator();

	@Override
	public EventListenerProvider create(KeycloakSession session) {
		SINGLETON.session = session;
		return SINGLETON;
	}

	@Override
	public void init(Scope config) { }

	@Override
	public void postInit(KeycloakSessionFactory factory) { 
	
	}

	@Override
	public void close() { }

	@Override
	public String getId() {
		return "guardiankey-event-listener";
	}

}
