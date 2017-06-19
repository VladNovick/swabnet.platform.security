package com.swabnet.platform.security.kerberos.clientserver;

import java.io.*;
import java.util.*;
import java.security.*;
import org.ietf.jgss.*;
import java.net.Socket;
import javax.security.auth.login.*;
import javax.security.auth.Subject;

/**
 * @author vladimir.novick
 *
 */
class JAASClient implements java.security.PrivilegedAction {

    JASSCallbackHandler beanCallbackHandler = null;

    LoginContext peerLC = null;
	
    Socket socket = null;
    DataInputStream inStream; 
    DataOutputStream outStream;

    String clientName = null;
    String serverName = null;

    String serverAddress = null;
    int serverPort;
	
    String confName = null;


    public static void main(String[] args) {

/* 
    	if (args.length < 9) {
	      System.err.println("Usage: java <options> KrberosLogin "
                     + " <clientname> <password> <servername> "
                     + "<serveraddress> <server port> \r\n" 
                     + " <realm address> <kdc address> "
                     + "<name and path of conf file > & <conf name");
            System.exit(-1);
        }
*/
		System.setProperty("sun.security.krb5.debug","true");
        JAASClient gssClient = new JAASClient ("vladimir.novick", //args[0]/*client name*/ , 
                                             "AQ1sw2de3fr4gt5hy6", // args[1]/*password*/, 
                                             "vladimir.novick", //args[2]/*clientName*/,
                                             "DEV4", //args[3]/*serveraddress*/,
                                             88, //Integer.parseInt(args[4])/*serverport*/, 
                                             "PRIMAGRID.COM", //args[5]/*kerberos realm name*/,
                                             "primag-host2", //args[6]/*kdc addres*/,
                                             "C:\\Development\\SwabNetSecurity\\com.swabnet.platform.security.kerberos.clientserver\\login.conf", //args[5]/*confFile*/, 
                                             "JAASClient"); //args[8]/*conf name*/ );

        GSSContext context = gssClient.login();
        if (context!=null)
        {
            String response = null; 
            //Checking confidentiality status of context.
            if (context.getConfState())
            {
                response = gssClient.sendMessage(context, "A sample message from client");
                System.out.println ("Server Response "+response);
            }
                       
            try {
                gssClient.getLoginContext().logout();
                context.dispose();
            } catch (Exception e) {
                e.printStackTrace();
            }//catch
			
        }
        else
            System.out.println("Client authentication deined...");
			
    }//main
	
    //The JAASClient constructor only sets all the required parameters.
    public JAASClient (String clientName, String password, 
                      String serverName, String serverAddress, 
                      int serverPort, String kerberosRealm, 
                      String kdcAddress, String confFile, String confName)
    {
        //The beanCallbackHandler will require the name and password of the client.
        beanCallbackHandler = new JASSCallbackHandler(clientName, password);
        this.clientName = clientName;
        this.serverName = serverName;
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.confName = confName;
        System.setProperty("java.security.krb5.realm", kerberosRealm);
        System.setProperty("java.security.krb5.kdc", kdcAddress);
        System.setProperty("java.security.auth.login.config", confFile);

        System.out.println(this.clientName);
    }// KerberoseLoginBean


    public GSSContext login()
    {
        try {
             peerLC = new LoginContext(confName, beanCallbackHandler);
             peerLC.login();
			
             socket = new Socket(serverAddress, serverPort);
             inStream = new DataInputStream(socket.getInputStream());
             outStream = new DataOutputStream(socket.getOutputStream());

             return (GSSContext) Subject.doAs( peerLC.getSubject(), this);
        }
       catch (Exception e) {
             System.out.println( ">>>> JAASClient....Secure Context not established.." );
             e.printStackTrace();
        	 return null;
        }//catch

    }//establishSecureContextWithServer
	

    //This is the only method in PrivilegedAction interface.
	//It receives control only in case of successful authentication of the client.
    public Object run() {
    try
	   {
           GSSManager manager = GSSManager.getInstance();
           Oid kerberos = new Oid("1.2.840.113554.1.2.2");
		   
           GSSName clientPeerName = manager.createName(
                    //Name of the client for which we want to create this GSSName object.
                    clientName ,
                    //Type of GSSName. Our client is a Windows user, 
                    //which we can specifiy using GSSName.NT_USER_NAME property.
                    GSSName.NT_USER_NAME);

           GSSName remotePeerName = manager.createName(serverName, GSSName.NT_USER_NAME);
           System.out.println (">>> JAASClient... Getting client credentials");

           GSSCredential peerCredentials = manager.createCredential(
                          //The GSSName object of the client.
                          clientPeerName,
                          //Time for which credentials whill be valid.
                          10*60,
                          //Kerberos mecahnism identifier.
                          kerberos,
                          //The client only intiates the secure context request.
                          GSSCredential.INITIATE_ONLY);
 
           System.out.println (">>> JAASClient... GSSManager creating security context");
           GSSContext peerContext = manager.createContext(remotePeerName,
                            kerberos,
                            peerCredentials,
                            GSSContext.DEFAULT_LIFETIME);
 

           peerContext.requestConf(true);
           byte[] byteToken = new byte[0];

           System.out.println (">>> JAASClient... Sending token to server over secure context");	
		   
           while (!peerContext.isEstablished()) {
      	        byteToken = peerContext.initSecContext(byteToken, 0, byteToken.length);

                if (byteToken != null) {
                    outStream.writeInt(byteToken.length);
                    outStream.write(byteToken );
                    outStream.flush();
                }//if

                if (!peerContext.isEstablished()) {
                    byteToken  = new byte[inStream.readInt()];
                    inStream.readFully(byteToken );
                }//if 
            }//while (!peerContext...)

            return peerContext; 
        
         }//try

         catch(org.ietf.jgss.GSSException ge) {
             System.out.println (">>> JAASClient... GSS Exception "+ge.getMessage());
         }

         catch(java.lang.Exception e) {
             System.out.println (">>> JAASClient... Exception "+e.getMessage());
         }//catch
         return null;
    }//run
   

    //Sends a message to the remote server on an already established context.
    //It returns the reply from the remote server.
    public String sendMessage(GSSContext context, String message)
    {
        byte[] serverMessage = null;
		byte[] clientMessage = null;

        MessageProp msgProp =  new MessageProp(0, true);
	
        try {

            System.out.println(">>> JAASClient... Client message is ["+message+"]");
            clientMessage = context.wrap(message.getBytes(), 0,
                                         message.getBytes().length, msgProp);
            outStream.writeInt(clientMessage.length);
            outStream.write(clientMessage);
            outStream.flush();
	
            //Receiving server response and sending back to client.
            serverMessage = new byte[inStream.readInt()];
            inStream.readFully(serverMessage);
            serverMessage = context.unwrap(serverMessage, 0,
                                           serverMessage.length, msgProp);
            System.out.println(">>> JAASClient... Server message is ["+serverMessage+"]");
            return new String (serverMessage);
        } catch(Exception e){
		    e.printStackTrace();
			return null;
        }
		
    }//sendMessage

    //It returns the established login context to client.
    public LoginContext getLoginContext()
    {
        return peerLC;
    }//getloginContext

}//JAASClient


