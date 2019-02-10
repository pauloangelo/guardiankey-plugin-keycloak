package io.guardiankey.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import javax.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;


// https://github.com/briantward/keycloak-custom/blob/master/providers/src/main/java/org/keycloak/custom/authentication/authenticators/SecretQuestionAuthenticator.java

public class GuardianKeyAuthenticator implements Authenticator {

	@Override
	public void close() { }

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		
		
		if(!true){
			   Response challenge = context.form()
			                .setError("something")
			                .createForm("error_page.ftl");

			 context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
			   return;
			}
			context.success();
		
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public boolean requiresUser() { return true; }

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {return true;}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }

}
