package io.guardiankey.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class GuardianKeyAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {


    public static final String PROVIDER_ID = "secret-question-authenticator";
    private static final GuardianKeyAuthenticator SINGLETON = new GuardianKeyAuthenticator();
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property1;
        property1 = new ProviderConfigProperty();
        property1.setName("guardiankey.orgid");
        property1.setLabel("Organization ID");
        property1.setHelpText("Hash to identify your organization for GuardianKey.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty property2;
        property2 = new ProviderConfigProperty();
        property2.setName("guardiankey.authgroupid");
        property2.setLabel("AuthGroup ID");
        property2.setHelpText("Hash to identify your authentication group for GuardianKey.");
        property2.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty property3;
        property3 = new ProviderConfigProperty();
        property3.setName("guardiankey.key");
        property3.setLabel("Key");
        property3.setHelpText("The key for cryptographics, in base64.");
        property3.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty property4;
        property4 = new ProviderConfigProperty();
        property4.setName("guardiankey.iv");
        property4.setLabel("IV");
        property4.setHelpText("The IV (Initialization Vector) for the key, in base64.");
        property4.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty property5;
        property5 = new ProviderConfigProperty();
        property5.setName("guardiankey.service");
        property5.setLabel("Service name");
        property5.setHelpText("A service name to identify the service provider. E.g., 'KeyCloak'.");
        property5.setType(ProviderConfigProperty.STRING_TYPE);
        ProviderConfigProperty property6;
        property6 = new ProviderConfigProperty();
        property6.setName("guardiankey.reverse");
        property6.setLabel("Reverse DNS");
        property6.setHelpText("Enable reverse DNS resolve?");
        property6.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        // reverse
        // service identification
        
        configProperties.add(property1);
        configProperties.add(property2);
        configProperties.add(property3);
        configProperties.add(property4);
        configProperties.add(property5);
        configProperties.add(property6);
    }
    
	
	@Override
	public Authenticator create(KeycloakSession session) { return SINGLETON; }

	@Override
	public void init(Scope config) { }

	@Override
	public void postInit(KeycloakSessionFactory factory) { }

	@Override
	public void close() { }

	@Override
	public String getId() {
		 return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		 return "A secret question that a user has to answer. i.e. What is your mother's maiden name.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		 return configProperties;
	}
	
	@Override
	public String getDisplayType() {
		return "GuardianKey Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return "GuardianKey";
	}

	@Override
	public boolean isConfigurable() {return true;}

	@Override
	public Requirement[] getRequirementChoices() {        
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {return false;}

}
