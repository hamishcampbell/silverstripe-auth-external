<?php
/**
 * LDAP log-in form
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 * @author Silverstripe team; I copied lots of code from them
 */
class LDAPLoginForm extends LoginForm {

	/**
	 * Constructor
	 *
	 * @param Controller $controller The parent controller, necessary to
	 *                               create the appropriate form action tag.
	 * @param string $name The method on the controller that will return this
	 *                     form object.
	 * @param FieldSet|FormField $fields All of the fields in the form - a
	 *                                   {@link FieldSet} of {@link FormField}
	 *                                   objects.
	 * @param FieldSet|FormAction $actions All of the action buttons in the
	 *                                     form - a {@link FieldSet} of
	 *                                     {@link FormAction} objects
	 * @param bool $checkCurrentUser If set to TRUE, it will be checked if a
	 *                               the user is currently logged in, and if
	 *                               so, only a logout button will be rendered
	 */
  function __construct($controller, $name, $fields = null, $actions = null,
                       $checkCurrentUser = true) {

		$this->authenticator_class = 'LDAPAuthenticator';

		$customCSS = project() . '/css/ldap_login.css';
		if(Director::fileExists($customCSS)) {
			Requirements::css($customCSS);
		}

		if(isset($_REQUEST['BackURL'])) {
			$backURL = $_REQUEST['BackURL'];
		} else {
			$backURL = Session::get('BackURL');
		}

      if($checkCurrentUser && Member::currentUserID()) {
        $fields = new FieldSet();
        $actions = new FieldSet(new FormAction("logout", "Log in as someone else"));
      } else {
        if(!$fields) {
          $searchfor = LDAPAuthenticator::getSearchFor();
          $fields = new FieldSet(
               new HiddenField("AuthenticationMethod", null, $this->authenticator_class, $this),
        			new TextField("LDAPAttribute", $searchfor["description"], 
        			              Session::get('SessionForms.LDAPLoginForm.LDAPAttribute')),
					new EncryptField("LDAPPassword", "LDAP Password"),
					new CheckboxField("Remember", "Remember me next time?",
					                  Session::get('SessionForms.LDAPLoginForm.Remember'))
          );
        }
        if(!$actions) {
          $actions = new FieldSet(
            new FormAction("dologin", "Log in")
          );
        }
      }

		if(isset($backURL)) {
			$fields->push(new HiddenField('BackURL', 'BackURL', $backURL));
		}

		parent::__construct($controller, $name, $fields, $actions);
  }


	/**
	 * Get message from session
	 */
  protected function getMessageFromSession() {
    parent::getMessageFromSession();
    if(($member = Member::currentUser()) && !Session::get('LDAPLoginForm.force_message')) {
      $this->message = "You're logged in as $member->FirstName.";
    }
    Session::set('LDAPLoginForm.force_message', false);
  }


  /**
	* Login form handler method
	*
	* This method is called when the user clicks on "Log in"
	*
	* @param array $data Submitted data
	*/
	public function dologin($data) {
		if($this->performLogin($data)) {
			Session::clear('SessionForms.LDAPLoginForm.LDAPAttribute');
			Session::clear('SessionForms.LDAPLoginForm.Remember');

			if($backURL = $_REQUEST['BackURL']) {
				Session::clear("BackURL");
				Director::redirect($backURL);
			} else
				Director::redirectBack();

		} else {
			Session::set('SessionForms.LDAPLoginForm.LDAPAttribute', $data['LDAPAttribute']);
			Session::set('SessionForms.LDAPLoginForm.Remember', isset($data['Remember']));
			if($badLoginURL = Session::get("BadLoginURL")) {
				Director::redirect($badLoginURL);
			} else {
				// Show the right tab on failed login
				Director::redirect(Director::absoluteURL(Security::Link("login")) .
													              '#' . $this->FormName() .'_tab');
			}
		}
	}

  /**
   * Try to authenticate the user
   *
   * @param array Submitted data
   * @return Member Returns the member object on successful authentication
   *                or NULL on failure.
   */
	public function performLogin($data) {
		if($member = LDAPAuthenticator::authenticate($data, $this)) {
			$member->LogIn(isset($data['Remember']));
			return $member;
		} else {
			return null;
		}
	}


	/**
	 * Log out form handler method
	 *
	 * This method is called when the user clicks on "logout" on the form
	 * created when the parameter <i>$checkCurrentUser</i> of the
	 * {@link __construct constructor} was set to TRUE and the user was
	 * currently logged in.
	 */
  public function logout() {
    $s = new Security();
    $s->logout();
  }

}

