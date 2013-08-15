package com.simplifyops.jaas.pam;

import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Abstract base login module for using libpam4j to authenticate.
 */
public abstract class AbstractPamLoginModule implements LoginModule {
    public static final Logger logger = Logger.getLogger(AbstractPamLoginModule.class.getName());
    private Map<String, ?> shared;
    private String serviceName;
    private CallbackHandler handler;
    private Subject subject;
    private boolean authenticated;
    private boolean committed;
    private UnixUser unixUser;
    private boolean useUnixGroups;
    private Principal userPrincipal;
    private List<Principal> rolePrincipals;
    private boolean debug;
    private List<String> supplementalRoles;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> shared, Map<String,
            ?> options) {
        this.handler = callbackHandler;
        this.subject = subject;
        this.shared = shared;
        Object service = options.get("service");
        if (null == service) {
            throw new IllegalStateException("service is required");
        }
        this.serviceName = service.toString();

        Object useUnixGroups1 = options.get("useUnixGroups");
        if (null != useUnixGroups1) {
            this.useUnixGroups = Boolean.parseBoolean(useUnixGroups1.toString());
        } else {
            this.useUnixGroups = false;
        }
        Object debug1 = options.get("debug");
        if (null != debug1) {
            this.debug = Boolean.parseBoolean(debug1.toString());
        }
        Object supplementalRoles1 = options.get("supplementalRoles");
        if (null != supplementalRoles1) {
            this.supplementalRoles = new ArrayList<String>();
            this.supplementalRoles.addAll(Arrays.asList(supplementalRoles1.toString().split(", +")));
        }
    }

    @Override
    public boolean login() throws LoginException {
        setAuthenticated(authenticate());
        return isAuthenticated();
    }

    protected boolean authenticate() throws LoginException {
        try {
            if (handler == null) {
                throw new LoginException("No callback handler");
            }
            Callback[] callbacks = createCallbacks();
            handler.handle(callbacks);
            String name = ((NameCallback) callbacks[0]).getName();
            char[] password = getPassword(callbacks[1]);
            if ((name == null) || (password == null)) {
                if (debug) {
                    debug("user or pass is null");
                }
                setAuthenticated(false);
                return isAuthenticated();
            }
            if (debug) {
                debug("PAM authentication trying (" + serviceName + ") for: " + name);
            }
            UnixUser authenticate = new PAM(serviceName).authenticate(name, new String(password));
            if (debug) {
                debug("PAM authentication succeeded for: " + name);
            }
            this.unixUser = authenticate;
            createPrincipals();
            setAuthenticated(true);
        } catch (IOException e) {
            if (debug) {
                e.printStackTrace();
            }
            throw new LoginException(e.toString());
        } catch (UnsupportedCallbackException e) {
            if (debug) {
                e.printStackTrace();
            }
            throw new LoginException(e.toString());
        } catch (PAMException e) {
            debug(e.getMessage());
            if (debug) {
                e.printStackTrace();
            }
            setAuthenticated(false);
        }
        return isAuthenticated();
    }

    /**
     * Emit Debug message via System.err by default
     *
     * @param message
     */
    protected void debug(String message) {
        logger.log(Level.INFO, message);
    }

    /**
     * Retrieve password from the callback
     *
     * @param callback
     *
     * @return
     */
    protected abstract char[] getPassword(Callback callback);

    /**
     * Set the principals for the Subject
     */
    private void setSubjectPrincipals() {
        if (null != userPrincipal) {
            this.subject.getPrincipals().add(userPrincipal);
        }
        if (null != rolePrincipals) {
            for (Principal rolePrincipal : rolePrincipals) {
                this.subject.getPrincipals().add(rolePrincipal);
            }
        }
    }

    private void createPrincipals() {
        this.userPrincipal = createUserPrincipal(unixUser);
        this.rolePrincipals = createRolePrincipals(unixUser);
    }

    private void clearSubjectPrincipals() {
        if (null != userPrincipal) {
            this.subject.getPrincipals().remove(userPrincipal);
            userPrincipal = null;
        }
        if (null != rolePrincipals) {
            this.subject.getPrincipals().removeAll(rolePrincipals);
            rolePrincipals = null;
        }
    }

    /**
     * Create a Principal for the user
     *
     * @param user
     *
     * @return
     */
    protected abstract Principal createUserPrincipal(UnixUser user);

    /**
     * Create a role Principal
     *
     * @param role
     *
     * @return
     */
    protected abstract Principal createRolePrincipal(String role);

    /**
     * Create Principals for any roles
     *
     * @param username
     *
     * @return
     */
    protected List<Principal> createRolePrincipals(UnixUser username) {
        ArrayList<Principal> principals = new ArrayList<Principal>();
        if (null != supplementalRoles) {
            for (String supplementalRole : supplementalRoles) {
                Principal rolePrincipal = createRolePrincipal(supplementalRole);
                if (null != rolePrincipal) {
                    principals.add(rolePrincipal);
                }
            }
        }
        if (useUnixGroups) {
            for (String s : username.getGroups()) {
                Principal rolePrincipal = createRolePrincipal(s);
                if (null != rolePrincipal) {
                    principals.add(rolePrincipal);
                }
            }
        }
        return principals;
    }

    /**
     * Create the callbacks
     *
     * @return
     */
    protected abstract Callback[] createCallbacks();

    @Override
    public boolean commit() throws LoginException {
        if (!isAuthenticated()) {
            unixUser = null;
            setCommitted(false);
        } else {
            setSubjectPrincipals();
            setCommitted(true);
        }
        return isCommitted();
    }

    @Override
    public boolean abort() throws LoginException {
        unixUser = null;

        return isAuthenticated() && isCommitted();
    }

    @Override
    public boolean logout() throws LoginException {
        setAuthenticated(false);
        unixUser = null;
        clearSubjectPrincipals();
        return true;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public boolean isCommitted() {
        return committed;
    }

    public void setCommitted(boolean committed) {
        this.committed = committed;
    }

    public boolean isUseUnixGroups() {
        return useUnixGroups;
    }
}
