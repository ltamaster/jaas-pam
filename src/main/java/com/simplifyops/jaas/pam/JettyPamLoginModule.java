package com.simplifyops.jaas.pam;

import org.jvnet.libpam.UnixUser;
import org.mortbay.jetty.plus.jaas.JAASPrincipal;
import org.mortbay.jetty.plus.jaas.JAASRole;
import org.mortbay.jetty.plus.jaas.callback.ObjectCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import java.security.Principal;

/**
 * Jetty 6 login module using PAM, uses Jetty6 principal classes and authentication callback.
 */
public class JettyPamLoginModule extends AbstractPamLoginModule {
    @Override
    protected Principal createUserPrincipal(UnixUser user) {
        return new JAASPrincipal(user.getUserName());
    }

    @Override
    protected Principal createRolePrincipal(String role) {
        return new JAASRole(role);
    }

    @Override
    protected Callback[] createCallbacks() {
        Callback[] calls = new Callback[2];
        calls[0] = new NameCallback("Username: ");
        calls[1] = new ObjectCallback();
        return calls;
    }

    @Override
    protected char[] getPassword(Callback callback) {
        Object object = ((ObjectCallback) callback).getObject();
        if(object instanceof String){
            return object.toString().toCharArray();
        }else if(object instanceof char[]) {
            return (char[]) object;
        }
        return null;
    }
}
