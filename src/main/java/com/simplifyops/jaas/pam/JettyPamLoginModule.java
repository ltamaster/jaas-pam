package com.simplifyops.jaas.pam;

import org.jvnet.libpam.UnixUser;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;

/**
 * Jetty 6 login module using PAM, uses Jetty6 principal classes and authentication callback.
 */
public class JettyPamLoginModule extends AbstractPamLoginModule {
    @Override
    protected Principal createUserPrincipal(UnixUser user) {
        return JettySupport.createUserPrincipal(user.getUserName());
    }

    /**
     * Return the result of handling the Jetty callbacks
     *
     * @return
     *
     * @throws IOException
     * @throws UnsupportedCallbackException
     * @throws LoginException
     */
    protected Object[] getCallBackAuth() throws IOException, UnsupportedCallbackException, LoginException {
        return JettySupport.performCallbacks(getCallbackHandler());
    }

    @Override
    protected Principal createRolePrincipal(String role) {
        return JettySupport.createRolePrincipal(role);
    }
}
