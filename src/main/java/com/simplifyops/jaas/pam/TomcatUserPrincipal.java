package com.simplifyops.jaas.pam;

/**
 * Created by luisao on 08-11-16.
 */

import java.security.Principal;

public class TomcatUserPrincipal implements Principal {

    private String name;

    /**
     * Initializer
     *
     * @param name
     */
    public TomcatUserPrincipal(String name) {
        super();
        this.name = name;
    }

    /**
     * Set the name of the user
     *
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the name of the user
     *
     * @return
     */
    @Override
    public String getName() {
        return name;
    }
}
