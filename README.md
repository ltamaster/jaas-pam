JAAS Pam Authentication
-----------------------

This project provides a JAAS LoginModule to authenticate via PAM

Example JAAS configuration
--------

    example {
            com.simplifyops.jaas.pam.JettyPamLoginModule required
            debug="true"
            service="sshd"
            supplementalRoles="user"
            useUnixGroups="true"
    ;
    };

Install
-------

Create your jaas configuration file as above.

Copy the necessary jars into appropriate location, or add to your classpath:

* `jaas-pam-0.1.jar`
* `libpam4j-1.7.jar`
* `jna-3.5.0.jar`
