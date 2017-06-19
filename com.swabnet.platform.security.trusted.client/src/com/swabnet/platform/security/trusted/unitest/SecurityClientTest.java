package com.swabnet.platform.security.trusted.unitest;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Set;

import com.swabnet.platform.security.trusted.client.SecurityClient;


/**
 * @author vladimir.novick
 *
 */
public class SecurityClientTest {
	
	
	public static void main(String argv[]) {

		try {
			SecurityClient client = new SecurityClient();			
			
			checkNetworkConnected("Before login");
			printPrincipal(client);			
			
			client.login();
			
			client.getCredentials();

			checkNetworkConnected("After login");
			printPrincipal(client);
			
			Set<Object> privateCredentials = client.getPrivateCredentials();
			Set<Object> publicCredentials = client.getPublicCredentials();			

			
			client.execOperation(new TestProtectedOperation());

			
			client.logout();
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void printPrincipal(SecurityClient client) {
		Principal[] p = client.getPrincipals();

		System.out
				.println("Authenticated user has the following Principals:");
		for (Principal o : p) {
			System.out.println("\t" + o.toString());
		}
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
			
			
			testWebAccess();
			
			File f = new File("\\\\primag-host2\\Development\\vladimir\\xml\\datatypes.dtd");
			if (!f.canWrite()){
				System.out.println("Network Access denied for the user");
			} else {
				System.out.println("Network Access granted");
			}
			
			
			
		} catch (Exception e){
			System.out.println("Network Access denied for the user");
		}
	}

	public static void testWebAccess() {
		try {
		URL url = new URL("http://cybertron/iistest/1.txt");
		URLConnection connection = url.openConnection();
		connection.connect();
		InputStream inputstream = connection.getInputStream();
		 byte[] buf = new byte[1024];
		  int len;
		  while ((len = inputstream.read(buf)) > 0){
		    System.out.write(buf, 0, len);
		  }
			System.out.println("\n");		      
		  

		System.out.println("Web Access granted");
		} catch (Exception e){
			System.out.println("Web Access denied for the user");
		}
	}
	
	

}
