package com.simplifyops.jaas.pam;

import org.mortbay.jetty.plus.jaas.callback.ObjectCallback;
import org.mortbay.jetty.plus.jaas.spi.PropertyFileLoginModule;
import org.mortbay.jetty.plus.jaas.spi.UserInfo;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * Augments Jetty property file login module {@link PropertyFileLoginModule}, to only perform authentication
 * via property file login, handles shared credentials logic, and does not use property file roles.
 */
public class JettyAuthPropertyFileLoginModule extends AbstractSharedLoginModule {
    PropertyFileLoginModule module;
    UserInfo userInfo;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map shared, Map options) {
        super.initialize(subject, callbackHandler, shared, options);
        module = new PropertyFileLoginModule();
        module.initialize(subject, callbackHandler, shared, options);
    }

    /**
     * Uses jetty callbacks to retrieve auth credentials
     * @return
     * @throws IOException
     * @throws UnsupportedCallbackException
     * @throws LoginException
     */
    protected Object[] getCallBackAuth() throws IOException, UnsupportedCallbackException, LoginException {
        return JettySupport.performCallbacks(getCallbackHandler());
    }

    @Override
    protected Principal createUserPrincipal() {
        return JettySupport.createUserPrincipal(userInfo.getUserName());
    }

    /**
     * Does not generate role principals for the user.
     * @return
     */
    @Override
    protected List<Principal> createRolePrincipals() {
        //Do not use roles from property file.
        return null;
    }


    @Override
    protected boolean authenticate(String sharedUserName, char[] chars) throws LoginException {
        try {
            this.userInfo = module.getUserInfo(sharedUserName);
            if (null == this.userInfo) {
                debug(String.format("JettyAuthPropertyFileLoginModule: got userInfo is null"));
                return false;
            }
            boolean b = this.userInfo.checkCredential(new String(chars));
            debug(String.format("JettyAuthPropertyFileLoginModule: got userInfo, authenticatd? %s", b));
            return b;
        } catch (Exception e) {
            if (isDebug()) {
                e.printStackTrace();
            }
            return false;
        }
    }

    @Override
    public boolean commit() throws LoginException {
        if (!isAuthenticated()) {
            userInfo = null;
        }
        return super.commit();
    }

    @Override
    public boolean abort() throws LoginException {
        userInfo = null;

        return super.abort();
    }

    @Override
    public boolean logout() throws LoginException {

        userInfo = null;

        return super.logout();
    }
}
