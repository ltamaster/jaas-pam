package com.simplifyops.jaas.pam;

import org.jvnet.libpam.UnixUser;

import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;

/**
 * Created by luisao on 08-11-16.
 */
public class TomcatPamLoginModule  extends AbstractPamLoginModule {
    @Override
    protected Principal createUserPrincipal(UnixUser user) {
        return TomcatSupport.createUserPrincipal(user.getUserName());
    }

    /**
     * Return the result of handling the Tomcat callbacks
     *
     * @return
     *
     * @throws IOException
     * @throws UnsupportedCallbackException
     * @throws LoginException
     */
    protected Object[] getCallBackAuth() throws IOException, UnsupportedCallbackException, LoginException {
        return TomcatSupport.performCallbacks(getCallbackHandler());
    }

    @Override
    protected Principal createRolePrincipal(String role) {
        return TomcatSupport.createRolePrincipal(role);
    }
}
