package com.simplifyops.jaas.pam;


import java.security.Principal;

public class TomcatRolePrincipal implements Principal {

    private String name;

    /**
     * Initializer
     *
     * @param name
     */
    public TomcatRolePrincipal(String name) {
        super();
        this.name = name;
    }

    /**
     * Set the role name
     *
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the role name
     *
     * @return
     */
    @Override
    public String getName() {
        return name;
    }
}