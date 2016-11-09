JAAS Pam Authentication
-----------------------

This project provides a JAAS LoginModule to authenticate via PAM

Example JAAS configuration
--------

PAM for authentication on Jetty:

    example {
        com.simplifyops.jaas.pam.JettyPamLoginModule required
            debug="true"
            service="sshd"
            supplementalRoles="user"
            useUnixGroups="true"
    ;
    };
    


Combining the JettyPamLoginModule for authentication and JettyRolePropertyFileLoginModule for authorization roles only:

    combined {
        com.simplifyops.jaas.pam.JettyPamLoginModule requisite
            debug="true"
            service="sshd"
            supplementalRoles="user"
            storePass="true"
            useUnixGroups="true";

        com.simplifyops.jaas.pam.JettyRolePropertyFileLoginModule required
            debug="true"
            useFirstPass="true"
            file="/path/to/roles.properties";

    };

Use one property file for authentication, and one for authorization roles only:

    roles_via_file {
        com.simplifyops.jaas.pam.JettyAuthPropertyFileLoginModule requisite
            debug="true"
            storePass="true"
            file="/path/to/users.properties";

        com.simplifyops.jaas.pam.JettyRolePropertyFileLoginModule required
            debug="true"
            useFirstPass="true"
            file="/path/to/roles.properties";

    };
    

Example JAAS configuration on Tomcat
--------

Create a jaas-pam.config file with these settings

jaas-pam {
   com.simplifyops.jaas.pam.TomcatPamLoginModule required
       debug="true"
       service="sshd"
       supplementalRoles="user"
       useUnixGroups="true";
}


Add the JAASRealm settings to the server.xml

    <Realm  className="org.apache.catalina.realm.JAASRealm"
            appName="jaas-pam"
            userClassNames="com.simplifyops.jaas.pam.TomcatUserPrincipal"
            roleClassNames="com.simplifyops.jaas.pam.TomcatRolePrincipal"/>

Set to on the CATALINA_OPS (or JAVA_OPS) the path of the jaas-pam.config

-Djava.security.auth.login.config=/path/jaas-pam.config


Install
-------

Create your jaas configuration file as above.

Copy the necessary jars into appropriate location, or add to your classpath (on Tomcat put the jars on $CATALINA_BASE/lib folder):

* `jaas-pam-0.1.jar`
* `libpam4j-1.5.jar`
* `jna-3.2.2.jar`

Build
------

With gradle 1.7:

    gradle distZip

Artifact:

    build/distributions/jaas-pam-0.1.zip
