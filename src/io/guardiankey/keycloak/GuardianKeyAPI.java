package io.guardiankey.keycloak;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.keycloak.Config.Scope;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

import twitter4j.JSONException;
import twitter4j.JSONObject;

public class GuardianKeyAPI {

	private String authGroupID = "";
	private String APIURI="https://api.guardiankey.io";
	private byte[] key;
	private byte[] iv;
	private String orgId ="";
	private String service ="KeyCloak";
	private boolean reverse = true;

	public void setConfig(Scope config) {

		this.authGroupID = config.get("guardiankey.authgroupid");
		this.APIURI      = config.get("guardiankey.apiurl");
		this.orgId 		 = config.get("guardiankey.orgid");
		this.service 	 = config.get("guardiankey.service");
		this.reverse     = config.getBoolean("guardiankey.reverse");

		this.key = Base64.getDecoder().decode(config.get("guardiankey.key"));
		this.iv = Base64.getDecoder().decode(config.get("guardiankey.iv"));
		
		
//		guardiankey.emailmode
//		guardiankey.emailsubject
//		guardiankey.adminemail

		
	}

	private JSONObject postMsg(KeycloakSession session, String URI, String msg) {
		
		
		try {
			HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
			HttpClient client = provider.getHttpClient();
			HttpPost post = new HttpPost(URI);
			post.setHeader("Content-type", "application/json");
			post.setHeader("Accept", "text/plain");
			
		    StringEntity params =new StringEntity("{\"id\":\""+this.authGroupID+"\",\"message\":\""+msg+"\"} ");
		    
			post.setEntity(params);

			HttpResponse response = client.execute(post);

			if(response.getStatusLine().getStatusCode()!=200)
				return null;


			HttpEntity entity = response.getEntity();
			
//			Header encodingHeader = entity.getContentEncoding();
			// you need to know the encoding to parse correctly
//			Charset encoding = encodingHeader == null ? StandardCharsets.UTF_8 : 
//				Charsets.toCharset(encodingHeader.getValue());

			// use org.apache.http.util.EntityUtils to read json as string
			
			String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
			return new JSONObject(json);
			
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
		
	}
	
	private byte[] encrypt(String txtMsg) {
		
		
        IvParameterSpec iv = new IvParameterSpec(this.iv);
        SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
        
		try {
	        Cipher cipher;
			cipher = Cipher.getInstance("AES/CFB8/NoPadding");
	        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
	        return cipher.doFinal(txtMsg.getBytes("UTF-8"));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		return null;
	}
	
	public String createMsg(String username, String email, boolean loginFailed, String eventType, String clientIP) {
		
		Long genTime = System.currentTimeMillis()/1000;
		
		String txtMsg = "";
		
		
		
		return Base64.getEncoder().encodeToString(encrypt(txtMsg));
	}
	
	
	

	public Map<String,String> checkAccess(KeycloakSession session, String username, String email, boolean loginFailed, String eventType, String clientIP) {
		
		HashMap<String,String> returnObj = new HashMap<String,String>();
		String msg=createMsg(username,email,loginFailed,eventType, clientIP);
		String uri = this.APIURI+"/checkaccess";
		
		JSONObject o = postMsg( session,  uri,  msg);
		
		if(o==null) {
			returnObj.put("response", "ERROR");
		}else {
			try {
				returnObj.put("response",o.getString("response"));
			} catch (JSONException e) {
				returnObj.put("response", "ERROR");
			}
		}
		
		return returnObj;
	}

	public Map<String,String> sendEvent(KeycloakSession session, String username, String email, boolean loginFailed, String eventType, String clientIP) {

		HashMap<String,String> returnObj = new HashMap<String,String>();
		String msg=createMsg(username,email,loginFailed,eventType, clientIP);
		String uri = this.APIURI+"/sendevent";
		
		JSONObject o = postMsg( session,  uri,  msg);
		
		if(o==null) {
			returnObj.put("response", "ERROR");
		}else {
			try {
				returnObj.put("response",o.getString("response"));
			} catch (JSONException e) {
				returnObj.put("response", "ERROR");
			}
		}
		return returnObj;

	}


}
