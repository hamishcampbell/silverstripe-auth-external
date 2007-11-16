<?php

/**
 * LDAP authenticator and controller
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 */

class ExternalAuthenticator extends Authenticator {

   /**
    * Authentication type we are going to use
    * like LDAP/POP3/IMAP
    */
   protected static $authtype = "LDAP";
   
   /**
    * Hostname of the authentication server
    * Note that if you use encryption, you _must_ use the FQDN
    **/
   protected static $authserver = "localhost";
    
   /**
    * Authentication server port. 
    **/
   protected static $authport = null;
    
   /**
    * Description of user id
    */
   protected static $useriddesc = "User ID";
   /**
    * You can use SSL or TLS for encryption
    **/
   protected static $enc = null;
    
   /**
    * Add non existing members that exists in external source automatically?
    * Set to false to disable or group name to enable
    **/
   protected static $autoadd = false;

   /**
    * Options to pass to the selected authentication method
    */
   protected static $authoption = array();
   
   /**
    * Message that results from authenticating
    */
   protected static $authmessage = '';

   /**
    * Set the Authentication type
    *
    * @param string $authtype Protocol identifier
    */                               
   public static function setAuthType($authtype) {
       self::$authtype = $authtype;
   }


   /**
    * Get the Authentication Type
    *
    * @return string Protocol identifier
    */              
   public static function getAuthType() {
       return self::$authtype;
   }


   /**
    * Set the Authentication Server
    *
    * @param string $authserver Server identifier
    */                               
   public static function setAuthServer($authserver) {
       self::$authserver = $authserver;
   }
   
   /**
    * Get the Authentication Server
    *
    * @return string Server identifier
    */              
   public static function getAuthServer() {
       return self::$authserver;
   }
   
   /**
    * Set the authentication port
    *
    * @param int $ldapport Server identifier
    */                               
   public static function setAuthPort($authport) {
       self::$authport = $authport;
   }
   
   /**
    * Get the authentication Port
    *
    * @return int authport tcp port number
    */              
   public static function getAuthPort() {
       return self::$authport;
   }
   
   /**
    * Set the name of the user id
    *
    * @param string $useriddesc Description of user id
    */                               
   public static function setIdDesc($useriddesc) {
       self::$useriddesc = $useriddesc;
   }
   
   /**
    * Get the user id description
    *
    * @return string useriddesc Description
    */              
   public static function getIdDesc() {
       return self::$useriddesc;
   }
   
   /**
    * Enable tls/ssl
    *
    * @param string $enc set to ssl or tls
    */                               
   public static function setAuthEnc($enc) {
       $enc = strtolower($enc);
       if (in_array($enc,array("tls","ssl")))
       {
           self::$enc = $enc;
       }
   }
   
   /**
    * Get tls status
    *
    * @return bool tls on or off
    */              
   public static function getAuthEnc() {
       return self::$enc;
   }
   
   /**
    * Set option for the authentication method
    *
    * @param string $key keyname for the option
    * @param string $value value of the key
    */                               
   public static function setOption($key, $value) {
       self::$authoption["$key"] = $value;
   }
   
   /**
    * Get authentication option
    *
    * @param string $key Keyname for the value to return
    * @return string value of the corresponding key
    */              
   public static function getOption($key) {
       if (isset(self::$authoption["$key"])) {
           return self::$authoption["$key"];
       } else {
           return null;
       }
   }  
   
   /**
    * Set the current member auto-add status
    *
    * @param mixed $doadd false to disable or group name to enable
    */
   public static function setAutoAdd($doadd) {
          self::$autoadd = $doadd;
   }

   /**
    * Get the current member auto-add status
    *
    * @return bool Auto add ot not?
    */
   public static function getAutoAdd() {
       return self::$autoadd;
   }

   /**
    * Set a message as a result of authenticating
    * (to be used by the authentication drivers)
    *
    * @param string $message The message to set    
    */
   public static function setAuthMessage($message){
       self::$authmessage = $message;
   }
   
   /**
    * Get the authentication message
    *
    * @return string The message
    */
   public static function getAuthMessage() {
       return self::$authmessage;
   }
   
  /**
   * Callback function that is called when the authenticator is registered
   *
   * Use this method for initialization of a newly registered authenticator.
   * Just overload this method and it will be called when the authenticator
   * is registered.
   * <b>If the method returns FALSE, the authenticator won't be
   * registered!</b>
   *
   * @return bool Returns TRUE on success, FALSE otherwise.
   */
  protected static function on_register() {
      Object::add_extension('Member', 'ExternalAuthenticatedRole');
      Object::add_extension('Member_Validator', 'ExternalAuthenticatedRole_Validator');
      return parent::on_register();
  }

    
  /**
   * Method to authenticate an user
   *
   * @param array $RAW_data Raw data to authenticate the user
   * @param Form $form Optional: If passed, better error messages can be
   *                             produced by using
   *                             {@link Form::sessionMessage()}
   * @return bool Returns FALSE if authentication fails, otherwise the
   *              member object    
   */
  public static function authenticate(array $RAW_data, Form $form = null) {
      $auth_type     = self::getAuthType();
      $external_uid    = trim($RAW_data['External_UserID']);
      $external_passwd = $RAW_data['Password'];
      $userexists      = false;    //Does the user exist within SilverStripe?
        
      // User ID should not be empty
      // Password should not be empty as well, but we check this in the
      // external authentication method itself. 
      if (strlen($external_uid) == 0) {
          if (!is_null($form)) {
              $form->sessionMessage(sprintf(_t('ExternalAuthenticator.EnterUID', 'Please enter a %s') ,self::$useriddesc), 'bad');
      }
      return false;
      } 

      // Does the user exists within silverstripe?
      $SQL_identity = Convert::raw2sql($external_uid);
      if (!($member = DataObject::get_one("Member","Member.External_UserID = '$SQL_identity'"))) {
          if (!self::getAutoAdd()) {
              if(!is_null($form)) {
                  $form->sessionMessage(_t('ExternalAuthenticator.Failed', 'Authentication failed'),'bad');
              }
              return false;
          }
      } else {
          $userexists = true;
      }

      require_once 'drivers/' . $auth_type . '.php';
      $myauthenticator = $auth_type . '_Authenticator';
      $myauthenticator = new $myauthenticator();
      $result = $myauthenticator->Authenticate($external_uid, $external_passwd);

      if ($result) {
          // The external source verified our existence
          if (!$userexists) {
              // But SilverStripe denies our existence, so we add ourselves
              $memberdata["External_UserID"] = $SQL_identity;
              if(isset($result["firstname"])) {
                  $memberdata["FirstName"] = Convert::raw2sql($result["firstname"]);
              }

              if (isset($result["surname"])) {
                  $memberdata["Surname"]   = Convert::raw2sql($result["surname"]);
              } else {
                  $memberdata["Surname"]   = $SQL_identity;
              }
 
              if (isset($result["email"])) {
                  $memberdata["Email"]     = Convert::raw2sql($result["email"]);
              } else {
                  $memberdata["Email"]     = $SQL_identity;
              }

              // But before we write ourselves to the database we must check if
              // we do not already exist in another authentication mechanism
              // and that the group we'll be subscribed to exists
              if (!DataObject::get_one("Member","Member.Email = '".$memberdata["Email"]."'") &&
                  DataObject::get_one("Group","Group.Title = '" . Convert::raw2sql(self::getAutoAdd())."'")) {
                  $member = new Member;

                  $member->update($memberdata);
                  $member->ID = null;
                  $member->write();

                  Group::addToGroupByName($member, self::getAutoAdd());
              } else {
                  $form->sessionMessage(_t('ExternalAuthenticator.Failed'),'bad');
                  return false;
              }
          }

          Session::clear("BackURL");
          
          // Set the security message here. Else it will be shown on logout
          Session::set("Security.Message.message", self::$authmessage);
             Session::set("Security.Message.type", "good");
          return $member;
      } else {
          if(!is_null($form)) {   
              $form->sessionMessage(self::$authmessage,'bad');
          }
          return false;
      }
  }


  /**
   * Method that creates the login form for this authentication method
   *
   * @param Controller The parent controller, necessary to create the
   *                   appropriate form action tag
   * @return Form Returns the login form to use with this authentication
   *              method
   */
  public static function get_login_form(Controller $controller) {
      return Object::create("ExternalLoginForm", $controller, "LoginForm");
  }


  /**
   * Get the name of the authentication method
   *
   * @return string Returns the name of the authentication method.
   */
  public static function get_name() {
      return _t('ExternalAuthenticator.Title',"External Account");
  }
}

