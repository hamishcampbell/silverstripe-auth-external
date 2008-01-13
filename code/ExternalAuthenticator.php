<?php

/**
 * LDAP authenticator and controller
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 */

class ExternalAuthenticator extends Authenticator {

   /**
    * Array which contains the authentication details of all authentication
    * sources. The index of the array will function as the unique source ID
    * which will be stored with the user name to allow for the same user ID
    * in multiple sources
    **/
   protected static $authsources = array();
   
   /**
    * Description of user id
    * This description is used for all sources defined
    */
   protected static $useriddesc = "User ID";

   /**
    * Message that results from authenticating
    **/
   protected static $authmessage = '';
   
   /**
    * Do let users choose the authentication source ot doe we check sources
    * in sequence? The order of the sequence bij the order in which the 
    * createSource is done (see below)
    **/
   protected static $authsequential = false;

 
   /**
    * Creates an authentication source with default settings
    *
    * @param string $sourceid Source ID
    * @param string $authtype Authentication server type
    * @param string $nicename Nice name for source chooser on login form
    **/
   public static function createSource($sourceid, $authtype, $nicename) {
       self::$authsources["$sourceid"] = array( 
           "authtype" => $authtype,         //Driver
           "nicename" => $nicename,         //Name to show in source chooser
           "authserver" => "localhost",     //IP or DNS name of server
           "authport" => null,              //IP port to use
           "useriddesc" => "User ID",       //How do we refer to a user id
           "encryption" => null,            //Enable SSL or TLS encryption
           "autoadd" => false,              //Automatically add users?
           "authoption" => array()          //Driver specific options
       );
   }
   
   
   /**
    * Get all source ids
    *
    * return array Array of source id's
    **/
   public static function getSources() {
       return array_keys(self::$authsources);   
   }
   
   /**
    * Get an array with the source ids as key and the nicenames as value
    * handdy for creating forms
    **/
   public static function getIDandNames() {
       $result = array();
       $keys   = array_keys(self::$authsources);
       
       foreach ($keys as $sourceid) {
           $result[$sourceid] = self::$authsources["$sourceid"]["nicename"];
       }
  
       return $result;
   }

 
   /**
    * Get the Authentication Type
    *
    * @param  string $sourceid Source ID
    * @return string Protocol identifier
    **/              
   public static function getAuthType($sourceid) {
       return self::$authsources["$sourceid"]["authtype"];
   }
   
   
   /**
    * Get the source nice name
    *
    * @param  string $sourceid Source ID
    * @return string Nice name
    **/              
   public static function getNiceName($sourceid) {
       return self::$authsources["$sourceid"]["nicename"];
   } 

   /**
    * Set the Authentication Server
    *
    * @param string $sourceid   Source ID
    * @param string $authserver Server identifier
    */                               
   public static function setAuthServer($sourceid, $authserver) {
       self::$authsources["$sourceid"]["authserver"] = $authserver;
   }
   
   /**
    * Get the Authentication Server
    *
    * @param  string $sourceid Source ID
    * @return string Server identifier
    */              
   public static function getAuthServer($sourceid) {
       return self::$authsources["$sourceid"]["authserver"];
   }
   
   /**
    * Set the authentication port
    *
    * @param string $sourceid Source ID
    * @param string $authport TCP port
    */                               
   public static function setAuthPort($sourceid, $authport) {
       self::$authsources["$sourceid"]["authport"] = $authport;
   }
   
   /**
    * Get the authentication Port
    *
    * @param  string $sourceid Source ID
    * @return int authport tcp port number
    */              
   public static function getAuthPort($sourceid) {
       return self::$authsources["$sourceid"]["authport"];
   }
   
   /**
    * Enable tls/ssl
    *
    * @param string $sourceid Source ID
    * @param string $enc      set to ssl or tls
    */                               
   public static function setAuthEnc($sourceid, $enc) {
       $enc = strtolower($enc);
       if (in_array($enc,array("tls","ssl")))
       {
           self::$authsources["$sourceid"]["enc"] = $enc;
       }
   }
   
   /**
    * Get tls status
    *
    * @param  string $sourceid Source ID
    * @return string tls or ssl
    */              
   public static function getAuthEnc($sourceid) {
       return self::$authsources["$sourceid"]["enc"];
   }
   
   /**
    * Set option for the authentication method
    *
    * @param string $sourceid Source ID
    * @param string $key keyname for the option
    * @param string $value value of the key
    */                               
   public static function setOption($sourceid, $key, $value) {
       self::$authsources[$sourceid]["authoption"]["$key"] = $value;
   }
   
   /**
    * Get authentication option
    *
    * @param  string $sourceid Source ID
    * @param  string $key Keyname for the value to return
    * @return string value of the corresponding key
    */              
   public static function getOption($sourceid, $key) {
       if (isset(self::$authsources["$sourceid"]["authoption"]["$key"])) {
           return self::$authsources["$sourceid"]["authoption"]["$key"];
       } else {
           return null;
       }
   }  
   
   /**
    * Set the current member auto-add status
    *
    * @param string $sourceid Source ID
    * @param mixed  $doadd false to disable or group name to enable
    */
   public static function setAutoAdd($sourceid, $doadd) {
          self::$authsources["$sourceid"]["autoadd"] = $doadd;
   }

   /**
    * Get the current member auto-add status
    *
    * @param  string $sourceid Source ID
    * @return mixed  Auto add (groupname) or not?
    */
   public static function getAutoAdd($sourceid) {
       return self::$authsources["$sourceid"]["autoadd"];
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
    * Set the authentication checks to sequential or user chosable
    *
    * @param bool $sequential
    **/
   public static function setAuthSequential($sequential) {
       self::$authsequential = $sequential;
   }
     
   /** 
    * Do we let the user choose or do we check sources in sequence
    *
    * @return bool True for sequential checks
    **/
   public static function getAuthSequential() {
       return self::$authsequential;
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
      if (self::getAuthSequential()) {
          $sources = self::getSources();
      } else {
          $sources = array($RAW_data['External_SourceID']);
      }
      $external_uid    = trim($RAW_data['External_UserID']);
      $external_passwd = $RAW_data['Password'];     
      $userexists      = false;    //Does the user exist within SilverStripe?
      $authsuccess     = false;    //Initialization of variable  
      //Set authentication message for failed authentication
      //Could be used by the individual drivers      
      _t('ExternalAuthenticator.Failed', 'Authentication failed');
      
      // User ID should not be empty
      // Password should not be empty as well, but we check this in the
      // external authentication method itself. 
      if (strlen($external_uid) == 0) {
          if (!is_null($form)) {
              $form->sessionMessage(sprintf(_t('ExternalAuthenticator.EnterUID', 'Please enter a %s') ,self::$useriddesc), 'bad');
          }
          return false;
      } 
      $SQL_identity = Convert::raw2sql($external_uid);
      
      // Now we are going to check this user with each source from the source
      // array, until we succeed or utterly fail
      foreach ($sources as $source) {
          // Does the user exists within silverstripe?
          $SQL_source   = Convert::raw2sql($source);
          if (($member = DataObject::get_one("Member","Member.External_UserID = '$SQL_identity'".
                                             " AND Member.External_SourceID = '$SQL_source'"))) {
              $userexists = true;
          }      

          if ($userexists || self::getAutoAdd($source)) {   
              $auth_type = self::getAuthType($source);
        
              require_once 'drivers/' . $auth_type . '.php';
              $myauthenticator = $auth_type . '_Authenticator';
              $myauthenticator = new $myauthenticator();
              $result = $myauthenticator->Authenticate($source, $external_uid, $external_passwd);

              if ($result) {
                  $authsuccess = true;
                  break;
              }
          }
      }
      
      // An external source verified our existence
      if ($authsuccess && !$userexists && self::getAutoAdd($source)) {
          // But SilverStripe denies our existence, so we add ourselves
          $memberdata["External_UserID"]   = $SQL_identity;
          $memberdata["External_SourceID"] = $SQL_source;
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
          // the group we are subscribing to exists
          if (DataObject::get_one("Group","Group.Title = '" . Convert::raw2sql(self::getAutoAdd($source))."'")) {
              $member = new Member;

              $member->update($memberdata);
              $member->ID = null;
              $member->write();

              Group::addToGroupByName($member, self::getAutoAdd($source));
          } else {
              $authsuccess = false;
          }
      }


      if ($authsuccess) {
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

