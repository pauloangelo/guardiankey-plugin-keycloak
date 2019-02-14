package io.guardiankey.keycloak;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import twitter4j.JSONException;
import twitter4j.JSONObject;

public class GuardianKeyAPI {

	private String authGroupID = "";
	private String APIURI="https://api.guardiankey.io";
	private byte[] key;
	private byte[] iv;
	private String orgId ="";
	private String service ="KeyCloak";
	private String agentId ="KeyCloakServer";
	private boolean reverse = true;

	public void setConfig(Scope config) {
		this.authGroupID = config.get("guardiankey.authgroupid");
		this.APIURI      = config.get("guardiankey.apiurl");
		this.orgId 		 = config.get("guardiankey.orgid");
		this.service 	 = config.get("guardiankey.service");
		this.agentId     = config.get("guardiankey.agentid");
		this.reverse     = config.getBoolean("guardiankey.reverse");
		this.key         = Base64.getDecoder().decode(config.get("guardiankey.key"));
		this.iv          = Base64.getDecoder().decode(config.get("guardiankey.iv"));
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
			String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
			return new JSONObject(json);
			
//			Header encodingHeader = entity.getContentEncoding();
			// you need to know the encoding to parse correctly
//			Charset encoding = encodingHeader == null ? StandardCharsets.UTF_8 : 
//				Charsets.toCharset(encodingHeader.getValue());
			// use org.apache.http.util.EntityUtils to read json as string
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		} catch (Exception e) {
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
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
        
		return null;
	}
	
	public String createMsg(String username, String email, boolean loginFailed, String eventType, String clientIP, String userAgent) {
		
		Long genTime = System.currentTimeMillis()/1000;
		
		Map<String,String> sjson = new HashMap<String,String>();
		sjson.put("generatedTime",genTime.toString());
		sjson.put("agentId",agentId);
		sjson.put("organizationId",orgId);
		sjson.put("authGroupId",authGroupID);
		sjson.put("service",service);
		sjson.put("clientIP",clientIP);
		
		if(reverse)	{
			try {
				InetAddress ia = InetAddress.getByName(clientIP);
				sjson.put("clientReverse",ia.getCanonicalHostName());
			} catch (UnknownHostException e) {
				sjson.put("clientReverse","");
			}
		}else {
			sjson.put("clientReverse","");
		}
		sjson.put("userName",username);
		sjson.put("authMethod","");
		sjson.put("loginFailed",(loginFailed)? "1" : "0");
		sjson.put("userAgent",userAgent);
		sjson.put("psychometricTyped","");
		sjson.put("psychometricImage","");
		sjson.put("event_type",eventType);
		sjson.put("userEmail",email);
		
        Gson gson = new GsonBuilder().create();
        String txtMsg = gson.toJson(sjson);
        
		return Base64.getEncoder().encodeToString(encrypt(txtMsg));
		/*
        key = base64.b64decode(keyb64)
        iv  = base64.b64decode(ivb64)
        clientIP = getClientIP()
        UA = getUserAgent()
        sjson = {}
        sjson['generatedTime'] = timestamp
        sjson['agentId'] = agentid
        sjson['organizationId'] = orgid
        sjson['authGroupId'] = authgroupid
        sjson['service'] = GKconfig['service']
        sjson['clientIP'] = clientIP
        try:
            sjson['clientReverse'] = socket.gethostbyaddr(clientIP)[0] if reverse else ""
        except:
            sjson['clientReverse'] = ""
        sjson['userName'] = username
        sjson['authMethod'] = ''
        sjson['loginFailed'] = str(loginfailed)
        sjson['userAgent'] = UA
        sjson['psychometricTyped'] = ''
        sjson['psychometricImage'] = ''
        sjson['event_type'] = eventType
        sjson['userEmail'] = userEmail
        message = json.dumps(sjson)
*/
		
		
	}
		
	public Map<String,String> checkAccess(KeycloakSession session, String username, String email, boolean loginFailed, String eventType, String clientIP, String userAgent) {
		HashMap<String,String> returnObj = new HashMap<String,String>();
		String msg=createMsg(username,email,loginFailed,eventType, clientIP,userAgent);
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

	public Map<String,String> sendEvent(KeycloakSession session, String username, String email, boolean loginFailed, String eventType, String clientIP, String userAgent) {
		HashMap<String,String> returnObj = new HashMap<String,String>();
		String msg=createMsg(username,email,loginFailed,eventType, clientIP,userAgent);
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
