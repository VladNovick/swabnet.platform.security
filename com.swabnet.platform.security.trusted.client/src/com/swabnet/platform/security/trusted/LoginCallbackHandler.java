package com.swabnet.platform.security.trusted;
import java.io.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;

public class LoginCallbackHandler implements CallbackHandler {

  public void handle(Callback callbacks[]) throws IOException, UnsupportedCallbackException {
    for(int i=0;i<callbacks.length;i++) {
      if(callbacks[i] instanceof NameCallback) {
        NameCallback nc = (NameCallback) callbacks[0];
        System.err.print(nc.getPrompt());
        System.err.flush();
        String name = (new BufferedReader(new InputStreamReader(System.in))).readLine();
        nc.setName(name);
      } else {
        throw(new UnsupportedCallbackException(callbacks[i], "Callback handler not support"));
      }
    }
  }
}

