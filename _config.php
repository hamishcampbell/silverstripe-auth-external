<?php

/**
 * Add LDAP role to Member
 */
DataObject::add_extension('Member', 'LDAPAuthenticatedRole');

/**
  * LDAP server definitions
  * Change the parameters below to suit your LDAP server, or disable the LDAP
  * authentication method altogether
  */
Authenticator::register_authenticator("LDAPAuthenticator");

/**
  * Hostname of the LDAP server
  * you can specify it like a normal hostname or IP number, or
  * like ldap://hostname or ldaps://hostname. The latter will do
  * encrypted LDAP
  * Note that if you use encryption, you _must_ use the FQDN
  **/
LDAPAuthenticator::setLDAPServer("ldap://localhost"); 

/**
  * LDAP server port, normally 389 for normal LDAP or 636 for LDAPS
  **/
LDAPAuthenticator::setLDAPPort(389); 

/**
  * You can use TLS for encryption, make sure the LDAP server is
  * specified as ldap://..... and the port is 389 (or _not_ the
  * ldaps port
  **/
LDAPAuthenticator::setLDAPtls(false);

/**
  * The DN where your users reside. Be as specific as possible
  * to prevent unexpected guests in the CMS, so typically your
  * directory's base dn (o=.... or dc=....,dc=....) augmented with
  * the ou where the accounts are
  **/
LDAPAuthenticator::setBaseDN("ou=People,dc=silverstripe,dc=com");

/**
  * LDAP protocol version to use
  * If yor have set tls to true, the version must be 3
  **/
LDAPAuthenticator::setLDAPVersion(3); 

/**
  * You can use any unique attribute to authenticate as, this
  * mail, or uid, or any other unique attribute. The description
  * you use here will be put on the login form
  * First item is the attribute name, the second one the description
  **/
LDAPAuthenticator::setSearchFor("uid","User ID"); 

/**
  * If your LDAP has POSIX style user accounts with shadow support
  * (your LDAP is probably also used to authenticate users on UNIX
  * boxes, you can set expiration to yes. That way, when a user
  * account expires, ha can also not login to silverstripe
  **/
LDAPAuthenticator::setPasswdExpiration(true); 

/**
  * If your directory doesn't support anonymous searches you can
  * specify an account below that will be used to search for the
  * attribute containing the user ID as (dn, passwd)
  **/
//LDAPAuthenticator::setBindAs('cn="Directory Manager"','secret'); 


 	
?>
