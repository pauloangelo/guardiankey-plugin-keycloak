package io.guardiankey.keycloak;

import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;


// https://github.com/briantward/keycloak-custom/blob/master/providers/src/main/java/org/keycloak/custom/authentication/authenticators/SecretQuestionAuthenticator.java

public class GuardianKeyAuthenticator implements Authenticator, EventListenerProvider {
	
    public static final GuardianKeyAPI GKAPI = new GuardianKeyAPI();


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
		
		GKAPI.setConfig(config);
		
		String username=context.getUser().getUsername();
		
		String clientIP="";
		String userAgent="";
		try {
			 clientIP = context.getSession().getContext().getConnection().getRemoteAddr();
		} catch (Exception e) {	}
		
		try {
			List<String> userAgents = session.getContext().getRequestHeaders().getRequestHeader("User-agent");
			if(userAgents.size()>0)
				userAgent = userAgents.get(0);	
		} catch (Exception e) {	}
		
		boolean failed = false;
		
		if(context.getUser().getEmail()!=null) {
			email = context.getUser().getEmail();
		}else {
			email ="";
		}
		
		if(config.get("guardiankey.sendonly").equals("true")) {
			GKAPI.sendEvent(session,username,email,failed,"Authentication", clientIP,userAgent);
		}else {
			Map<String,String> checkReturn = GKAPI.checkAccess(session,username,email,failed,"Authentication", clientIP,userAgent);
			if(checkReturn.get("response").equals("BLOCK")) {
                 Response challenge = context.form()
							                .setError("blocked_attempt")
							                .createForm("error_page.ftl");
				 context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
				 return;
			}else if(checkReturn.get("response").equals("NOTIFY") || checkReturn.get("response").equals("HARD_NOTIFY")) {
				sendEmail(username,email,context,checkReturn);
			}
		}
		context.success();
		return;
	}

	private void sendEmail(String username, String email, AuthenticationFlowContext context, Map<String, String> checkReturn) {
		Map<String,String> config = context.getAuthenticatorConfig().getConfig();

		
		if(config.get("guardiankey.emailmode")==null || config.get("guardiankey.emailmode").equals("None"))
			return;
		
		Map<String,String> configSMTP = context.getRealm().getSmtpConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		String subject = (config.get("guardiankey.emailsubject")!=null)? config.get("guardiankey.emailsubject") : "";
		String textBody = "Hi";
		String htmlBody = "Hi";
        EmailSenderProvider emailSender = session.getProvider(EmailSenderProvider.class);
        
//        FreeMarkerUtil freeMarker = new FreeMarkerUtil();
//        htmlBody = freeMarker.processTemplate(attributes, htmlTemplate, theme);
        
        try {
			emailSender.send(configSMTP, user, subject, textBody, htmlBody);
		} catch (EmailException e) {
		}
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
	
	public void setConfig(Scope config) {
		if (config==null)
			return;
		
	}
	
	// https://www.keycloak.org/docs/3.3/server_development/topics/providers.html

	@Override
	public void onEvent(Event event) {

//		event.getSessionId() 
		
		
		 String clientIP = event.getIpAddress();
//        if (event.getType().equals("LOGIN_ERROR")) {
        if (event.getType().equals(EventType.LOGIN_ERROR)) {


        }
	}

	@Override
	public void onEvent(AdminEvent event, boolean includeRepresentation) {	}

}



