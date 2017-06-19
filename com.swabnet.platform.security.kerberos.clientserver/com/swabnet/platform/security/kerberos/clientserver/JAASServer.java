package com.swabnet.platform.security.kerberos.clientserver;



import org.ietf.jgss.*;
import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;


import java.util.*;
import java.security.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.Subject;
import com.sun.security.auth.callback.TextCallbackHandler;


/**
 * A GSS server who accepts a request from a client.
 * 
 * @author vladimir.novick
 *
 */
public class JAASServer implements java.security.PrivilegedAction {

//Handles callback from the JAAS framework.
JASSCallbackHandler beanCallbackHandler = null;

//The main object that handles all JAAS login.
LoginContext serverLC = null;    

//The context for secure communication with client.
GSSContext serverGSSContext = null;

//Socket and streams used for communication.
ServerSocket serverSocket = null;
DataInputStream inStream = null; 
DataOutputStream outStream = null;

//Name and port of server.
String serverName = null;
int serverPort;

//Configuration file and the name of the client configuration.
String confFile = null;
String confName = null;

public static void main(String[] args) 
       throws IOException, GSSException 
{

/*   if (args.length < 6) {
        System.err.println("Usage: java <options> RemoteServer "
                            +"  <server name> <port> <relam> "
                            +"  <kdc> <conf file> <conf name>");
        System.exit(-1);
    }
*/	
	GSSContext context = null;
	System.setProperty("sun.security.krb5.debug","true");	
    JAASServer server = new JAASServer ("vladimir.novick", //args[0]/*serverName*/, 
                                      "AQ1sw2de3fr4gt5hy6", //args[1]/*password*/,
                                      88, //Integer.parseInt(args[2])/*port*/,
                                      "PRIMAGRID.COM", //args[3]/*kerberos realm name*/,
                                      "primag-host2", //args[4]/*kdc address*/, 
                                      "C:\\Development\\SwabNetSecurity\\com.swabnet.platform.security.kerberos.clientserver\\login.conf", //args[5]/*confFile*/, 
                                      "JAASServer" ); //args[6]/*confName*/);
    
    //Starting the server.
    server.startServer();
  
}//main


//JAASServer constructor 
public JAASServer (String serverName, String password, 
                  int serverPort, String kerberosRealm, 
                  String kdcAddress, String confFile, String confName) 
{
    beanCallbackHandler = new JASSCallbackHandler(serverName, password);
    this.serverName = serverName;
    this.serverPort = serverPort;
    this.confName = confName;
    System.setProperty("java.security.krb5.realm", kerberosRealm);
    System.setProperty("java.security.krb5.kdc", kdcAddress);
    System.setProperty("java.security.auth.login.config", confFile);

}//JAASServer


public boolean startServer()
{			  

    try {
         serverLC = new LoginContext(confName, beanCallbackHandler);
         serverLC.login();
         Subject.doAs(serverLC.getSubject(), this); 
         return true;
    } catch (Exception e) {
         System.out.println(">>> JAASServer... Secure Context not established..");
         return false;
    }//catch
     
}//start


public Object run()
{
    try
    {
        serverSocket = new ServerSocket(serverPort);
        GSSManager manager = GSSManager.getInstance();
        Oid kerberos = new Oid("1.2.840.113554.1.2.2");


          System.out.println(">>> JAASServer starts... Waiting for incoming connection");

        GSSName serverGSSName = manager.createName(serverName,null);
	        GSSCredential serverGSSCreds = manager.createCredential(serverGSSName,
                                         GSSCredential.INDEFINITE_LIFETIME,
                                         kerberos,
                                         //The server accepts secure context request.
                                       GSSCredential.ACCEPT_ONLY);

          serverGSSContext = manager.createContext(serverGSSCreds);

          Socket clientSocket = serverSocket.accept();
          inStream = new DataInputStream(clientSocket.getInputStream());
          outStream = new DataOutputStream(clientSocket.getOutputStream());

          byte[] byteToken = null;

          while (!serverGSSContext.isEstablished()) 
          {
              byteToken = new byte[inStream.readInt()];
              inStream.readFully(byteToken);
              byteToken = serverGSSContext.acceptSecContext(byteToken, 0,
                                                            byteToken.length);

              if (byteToken!= null) 
              {
                  outStream.writeInt(byteToken.length);
                  outStream.write(byteToken);
                  outStream.flush();
               }//if
          }//while (!context.isEstablished())
			 
         String clientName =serverGSSContext.getTargName().toString();
         String serverName = serverGSSContext.getSrcName().toString();
         MessageProp msgProp = new MessageProp(0, false);

         byteToken = new byte[inStream.readInt()];
         inStream.readFully(byteToken);

         //Unwrapping and verifiying the received message.
         byte[] message = serverGSSContext.unwrap(byteToken, 0, 
                                                  byteToken.length, msgProp);
         System.out.println(">>> JAASServer Message ["+new String(message)+" ] received");

         //Wrapping the response message.
         message = new String(">>> JAASServer Secure Context establish between"
                               + "["+clientName+"] and ["+serverName+"]").getBytes();

         message = serverGSSContext.wrap(message, 0,
                                         message.length, msgProp);

         outStream.writeInt(message.length);
         outStream.write(message);
         outStream.flush();				 
         System.out.println(">>> JAASServer Message ["+new String(message)+"] sent");

         //Disposeing and closing client and server sockets.
         serverGSSContext.dispose();
         clientSocket.close();
         serverSocket.close();
         System.out.println(">>> JAASServer shutdown.... ");
     }//try
     catch(java.lang.Exception e){
         e.printStackTrace();
     }

   return null;
   
}//run

}//JAASServer
