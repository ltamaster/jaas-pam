package com.simplifyops.jaas.pam;

import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by luisao on 08-11-16.
 */
public class TomcatSupport {
    public static final Logger logger = Logger.getLogger(TomcatSupport.class.getName());

    private static Callback[] createCallbacks() {
        Callback[] calls = new Callback[2];
        calls[0] = new NameCallback("Username: ");
        calls[1] = new PasswordCallback("password", true);

        return calls;
    }

    public static Object[] performCallbacks(CallbackHandler handler) throws IOException,
            UnsupportedCallbackException, LoginException {
        if (handler == null) {
            throw new LoginException("No callback handler");
        }
        Callback[] callbacks = createCallbacks();
        handler.handle(callbacks);
        String name = ((NameCallback) callbacks[0]).getName();
        String creds = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());

        logger.log(Level.INFO, "Username: " + name);
        logger.log(Level.INFO, "Password: " +  creds);

        return new Object[]{name, getPassword(creds)};
    }

    private static char[] getPassword(Object object) {
        if (object instanceof String) {
            return object.toString().toCharArray();
        } else if (object instanceof char[]) {
            return (char[]) object;
        }
        return null;
    }

    public static Principal createUserPrincipal(String username) {
        return new TomcatUserPrincipal(username);
    }
    public static Principal createRolePrincipal(String rolename) {
        return new TomcatRolePrincipal(rolename);
    }

}
