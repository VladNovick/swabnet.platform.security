package com.swabnet.platform.security.kerberos.clientserver;


import java.io.*;
import java.security.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;


/**
 * Handles callback from JAAS framework. 
 * 
 * @author vladimir.novick
 *
 */
public class JASSCallbackHandler implements CallbackHandler {

// Store username and password.
String name = null;
String password = null;

public JASSCallbackHandler(String name, String password)
{
    this.name = name;
    this.password = password;
}//JASSCallbackHandler


public void handle (Callback[] callbacks) throws
    UnsupportedCallbackException, IOException 
{
    for(int i=0;i<callbacks.length;i++) {
        Callback callBack = callbacks[i];

        // Handles username callback.
        if (callBack instanceof NameCallback) {
            NameCallback nameCallback = (NameCallback)callBack;
            nameCallback.setName(name);

         // Handles password callback.
        } else if (callBack instanceof PasswordCallback) {
          PasswordCallback passwordCallback = (PasswordCallback)callBack;
          passwordCallback.setPassword(password.toCharArray());

      } else {
          throw new UnsupportedCallbackException(callBack, "Call back not supported");
      }//else
  }//for 
  
}//handle

}//JASSCallbackHandler