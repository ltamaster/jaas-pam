package com.simplifyops.jaas.pam;

import org.mortbay.jetty.plus.jaas.JAASPrincipal;
import org.mortbay.jetty.plus.jaas.JAASRole;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Extends Jetty property file login module {@link PropertyFileLoginModule}, to ignore authentication via property file
 * login, but match the username with supplied Role lists from the property file.
 */
public class JettyRolePropertyFileLoginModule extends AbstractSharedLoginModule {
    PropertyFileLoginModule module;
    UserInfo userInfo;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map shared, Map options) {
        super.initialize(subject, callbackHandler, shared, options);
        if(!isUseFirstPass() && !isTryFirstPass()) {
            throw new IllegalStateException("JettyRolePropertyFileLoginModule must have useFirstPass or tryFirstPass " +
                    "set to true");
        }
        module = new PropertyFileLoginModule();
        module.initialize(subject, callbackHandler, shared, options);
        debug("JettyRolePropertyFileLoginModule: initialized");
    }

    protected Object[] getCallBackAuth() throws IOException, UnsupportedCallbackException, LoginException {
        if(isHasSharedAuth()) {
            debug("getCallBackAuth: has shared");
            return new Object[]{getSharedUserName(), getSharedUserPass().toString().toCharArray()};
        }else {
            debug("getCallBackAuth: no shared");
            return new Object[]{null, null};
        }
    }

    @Override
    protected Principal createUserPrincipal() {
        //do not create user principal
        return null;
    }


    @Override
    protected List<Principal> createRolePrincipals() {

        ArrayList<Principal> roles = new ArrayList<Principal>();
        if (null != this.userInfo) {
            List roleNames = this.userInfo.getRoleNames();
            for (Object roleName : roleNames) {
                roles.add(createRolePrincipal(roleName.toString()));
            }
        }
        debug("createRolePrincipals: "+roles);
        return roles;
    }

    protected Principal createRolePrincipal(String role) {
        return JettySupport.createRolePrincipal(role);
    }

    @Override
    protected boolean authenticate(String sharedUserName, char[] chars) throws LoginException {
        if (!isHasSharedAuth()) {
            debug("JettyRolePropertyFileLoginModule: no shared auth, skipping.");
            return false;
        }
        try {
            this.userInfo = module.getUserInfo(sharedUserName);
            debug("JettyRolePropertyFileLoginModule: got userInfo for " + sharedUserName);
        } catch (Exception e) {
            if (isDebug()) {
                e.printStackTrace();
            }
        }
        return true;
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
