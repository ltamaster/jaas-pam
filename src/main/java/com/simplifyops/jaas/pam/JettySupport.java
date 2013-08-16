package com.simplifyops.jaas.pam;

import org.mortbay.jetty.plus.jaas.JAASPrincipal;
import org.mortbay.jetty.plus.jaas.JAASRole;
import org.mortbay.jetty.plus.jaas.callback.ObjectCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;

/**
 * $INTERFACE is ... User: greg Date: 8/16/13 Time: 10:26 AM
 */
public class JettySupport {
    private static Callback[] createCallbacks() {
        Callback[] calls = new Callback[2];
        calls[0] = new NameCallback("Username: ");
        calls[1] = new ObjectCallback();
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
        Object creds = ((ObjectCallback) callbacks[1]).getObject();
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
        return new JAASPrincipal(username);
    }
    public static Principal createRolePrincipal(String rolename) {
        return new JAASRole(rolename);
    }
}
