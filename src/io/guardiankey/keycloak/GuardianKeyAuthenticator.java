package io.guardiankey.keycloak;

import java.util.Map;

import javax.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;


// https://github.com/briantward/keycloak-custom/blob/master/providers/src/main/java/org/keycloak/custom/authentication/authenticators/SecretQuestionAuthenticator.java

public class GuardianKeyAuthenticator implements Authenticator {
	
    public final GuardianKeyAPI GKAPI = new GuardianKeyAPI();

	@Override
	public void close() { }

	@Override
	public void authenticate(AuthenticationFlowContext context) {
			
		String email;
		Map<String,String> config = context.getAuthenticatorConfig().getConfig();
		KeycloakSession session = context.getSession();
		
		if(context.getUser()==null) {
			return;
		}
		
		String username=context.getUser().getUsername();
		
		// TODO: Check
		String clientIP = context.getSession().sessions().getUserSession(null,null).getIpAddress();
		
		
		boolean failed = context.getStatus().equals(FlowStatus.SUCCESS);
		if(context.getUser().getEmail()!=null) {
			email = context.getUser().getEmail();
		}else {
			email ="";
		}
		
		
		if(config.get("guardiankey.sendonly").equals("true")) {
			GKAPI.sendEvent(session,username,email,failed,"Authentication", clientIP);
		}else {
			//TODO: Set timeout
			Map<String,String> checkReturn = GKAPI.checkAccess(session,username,email,failed,"Authentication", clientIP);
			
			if(checkReturn.get("response").equals("BLOCK")) {
                 Response challenge = context.form()
							                .setError("blocked_attempt")
							                .createForm("error_page.ftl");
				 context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
				 return;
			}else if(checkReturn.get("response").equals("NOTIFY") || checkReturn.get("response").equals("HARD_NOTIFY")) {
				sendEmail(context,checkReturn);
			}
		}
		
		context.success();
		return;
		
	}

	private void sendEmail(AuthenticationFlowContext context, Map<String, String> checkReturn) {
		// TODO Auto-generated method stub
		Map<String,String> config = context.getAuthenticatorConfig().getConfig();

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
