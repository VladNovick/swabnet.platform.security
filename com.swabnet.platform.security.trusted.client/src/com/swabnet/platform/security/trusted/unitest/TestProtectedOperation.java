/**
 * 
 */
package com.swabnet.platform.security.trusted.unitest;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessControlContext;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;

import javax.security.auth.Subject;

import com.swabnet.platform.security.trusted.ProtectedOperation;


/**
 * @author vladimir.novick
 *
 */
public class TestProtectedOperation extends ProtectedOperation {

	/* (non-Javadoc)
	 * @see com.swabnet.platform.security.trusted.ProtectedOperation#execute()
	 */
	@Override
	public Object run() {
		
		checkNetworkConnected(" Protected operation ");
		
		return null;
	}
	
	
	private static void checkNetworkConnected(String text) {
		System.out.println("\n  -------------------- " + text + " ---------------------");
		try {
			String java_home = System.getProperty("java.home");
			System.out.println("java.home=" + java_home);
			ProtectionDomain protectedDomain = File.class.getProtectionDomain();
			Principal[] p = protectedDomain.getPrincipals();
			System.out.println("File's principals:");
			for (Principal o : p) {
				System.out.println("\t" + o.toString());
			}			
			
			
			
			
			
			File f = new File("\\\\primag-host2\\Development\\vladimir\\xml\\datatypes.dtd");
			if (!f.canWrite()){
				System.out.println("Network Access denied for the user");
			} else {
				System.out.println("Network Access granted");
			}
			
			
			
		} catch (Exception e){
			System.out.println("Network Access denied for the user :" + e.getMessage());
		}
		
		
		SecurityClientTest.testWebAccess();
		
		
	}	
	
	

}
