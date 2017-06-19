package com.swabnet.platform.security.trusted.unitest;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.ietf.jgss.GSSManager;

/**
 * @author vladimir.novick
 *
 */
public class TestLoginModule implements LoginModule {

	protected Subject m_subject;
	  protected ArrayList m_principals = null;
	  public boolean commit() throws LoginException {
	    // Login succeeded, 
	    // add demo Principals to the Subject.
	    if (!(m_subject.getPrincipals().containsAll(
	                                m_principals))) {
	        m_subject.getPrincipals().addAll(
	                                   m_principals);
	    }		
	    return true;
	  }
	  public boolean logout() throws LoginException {
	    // Need to remove our 
	    // principals from the Subject.
	    if (null != m_principals) {
	      m_subject.getPrincipals().removeAll(
	                                   m_principals);
	      m_principals = null;
	    }
	    return true;
	  }
	public boolean abort() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}
	public void initialize(Subject arg0, CallbackHandler arg1, Map<String, ?> arg2, Map<String, ?> arg3) {
		// TODO Auto-generated method stub
		
	}
	
	
	private void printPermissions(){
//		 Get the protection domain for the class
		

	    ProtectionDomain domain = this.getClass().getProtectionDomain();
	    
	    // With the protection domain, get all the permissions from the Policy object
	    PermissionCollection pcoll = Policy.getPolicy().getPermissions(domain);
	    
	    // View each permission in the permission collection
	    Enumeration enumd = pcoll.elements();
	    for (; enumd.hasMoreElements(); ) {
	        Permission p = (Permission)enumd.nextElement();
	        System.out.println(p.toString());
	    }
		
	}
	
	
	public boolean login() throws LoginException {
		
		printPermissions();
		
		AccessControlContext ctxt = 
            AccessController.getContext();
       Subject subj = Subject.getSubject(ctxt);	
		
		
		GSSManager gssManager = GSSManager.getInstance();
		SecurityManager manager = System.getSecurityManager();
		if (manager == null){
			manager = new SecurityManager();
			System.setSecurityManager(manager);
		}

		Object securityContext = manager.getSecurityContext();
		try {
		manager.checkConnect("localhost", 1024);
		} catch (Exception e){
			e.printStackTrace();
		}
//		AccessControlContext ctxt = (AccessControlContext)securityContext;
//		Subject subj = Subject.getSubject(ctxt);
//		if (subj == null) {
		  //no authenticated user
//		} else {
//		  Set principalsSet = subj.getPrincipals();
//		  Iterator iter = principalsSet.iterator();
//		  while(iter.hasNext()) {
//		    MyPrincipalClass princ = 
//		      (MyPrincipalClass)iter.next();
//		    if (princ.getName().equals("MyUser")) {
		      // have an authenticated user
//		    }
//		  }
//		}		
		
		
		return true;
	}
	

}
