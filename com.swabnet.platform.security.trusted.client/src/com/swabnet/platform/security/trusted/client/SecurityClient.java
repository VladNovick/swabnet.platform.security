package com.swabnet.platform.security.trusted.client;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.swabnet.platform.security.trusted.LoginCallbackHandler;
import com.swabnet.platform.security.trusted.LoginConfiguration;
import com.swabnet.platform.security.trusted.ProtectedOperation;


/**
 * 
 * The class use to Windows Security Login/Logout process and performs the
 * security operation.
 * 
 * @author vladimir.novick
 *
 */
public class SecurityClient {
	
	
	public SecurityClient() throws LoginException{
	
		try {

			Configuration.setConfiguration(new LoginConfiguration());

			loginContext = new LoginContext("Login", new LoginCallbackHandler());
		} catch (LoginException le) {
			System.err.println("SecurityClient cannot be created. "
					+ le.getMessage());
			throw le;
		} catch (SecurityException se) {
			System.err.println("SecurityClient cannot be created. "
					+ se.getMessage());
			throw se;
		}		
		
	}

	private LoginContext loginContext = null;


	
	public Set<Object> getPrivateCredentials(){
		Subject subject = loginContext.getSubject();
		
		if (subject != null){
			return subject.getPrivateCredentials();
		}
		return null;
	}

	
	public Set<Object> getPublicCredentials(){
		Subject subject = loginContext.getSubject();
		
		if (subject != null){
			return subject.getPublicCredentials();
		}
		return null;
	}
	
	/**
	 *  run ProtectOperation as the impersonated user
	 * 
	 * @param operation
	 * @return
	 */
	public Object execOperation(ProtectedOperation operation){
	    Subject subject = loginContext.getSubject();

	    return Subject.doAs(subject, 
	    		operation);
		
	}
	
	
	
	public void getCredentials(){


		Subject subject = loginContext.getSubject();
		Set<Object> permissions = subject.getPublicCredentials();
		
		Iterator it = permissions.iterator();
		


	    for (; it.hasNext(); ) {
	        Object p = it.next();
	        System.out.println(p.toString());
	    }
		
	}	
	
	
	public Principal[] getPrincipals() {

		List<Principal> ret = new ArrayList<Principal>();
		
		Subject subject = loginContext.getSubject();
		
		if (subject != null){

			
		Iterator principalIterator = subject.getPrincipals()
				.iterator();

		while (principalIterator.hasNext()) {
			Principal p = (Principal) principalIterator.next();
			ret.add(p);
		}
		}

		Principal[] p = new Principal[ret.size()];
		if (ret.size() > 0) {
			ret.toArray(p);
		}

		return p;
	}

	public void logout() throws LoginException {
		loginContext.logout();
	}

	/**
	 * 
	 * 
	 * @throws LoginException
	 */
	public void login() throws LoginException {

	
		try {

			loginContext.login();
		} catch (LoginException le) {
			System.out.println("Authentication failed. " + le.getMessage());
			throw le;
		}

	}
}
