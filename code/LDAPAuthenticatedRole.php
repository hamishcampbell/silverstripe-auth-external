<?php

/**
 * LDAP authentication decorator
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 * @author Silverstripe team; I copied lots of code from them
 */



/**
 * Decorator for the member class to support LDAP authentication
 *
 * This class adds the needed fields to the default member class to support
 * authentication via LDAP.
 */
class LDAPAuthenticatedRole extends DataObjectDecorator {

	/**
	 * Define extra database fields
	 *
	 * Returns a map where the keys are db, has_one, etc, and the values are
	 * additional fields/relations to be defined
	 *
	 * @return array Returns a map where the keys are db, has_one, etc, and
	 *               the values are additional fields/relations to be defined
	 */
	function extraDBFields() {
		return array(
			'db' => array('LDAPAttribute' => 'Varchar(255)'),
			'has_one' => array(),
			'defaults' => array('LDAPAttribute' => null),
			'indexes' => array('LDAPAttribute' => 'unique (LDAPAttribute)')
		);
	}


	/**
	 * Edit the given query object to support queries for this extension
	 *
	 * At the moment this method does nothing.
	 *
	 * @param SQLQuery $query Query to augment.
	 */
	function augmentSQL(SQLQuery &$query) {
	}


	/**
	 * Update the database schema as required by this extension
	 *
	 * At the moment this method does nothing.
	 */
	function augmentDatabase() {
	}


	/**
	 * Change the member dialog in the CMS
	 *
	 * This method updates the form in the member dialog to make it possible
	 * to edit the new database fields.
	 */
	function updateCMSFields(FieldSet &$fields) {
	   $searchfor = LDAPAuthenticator::getSearchFor();
		$fields->push(new HeaderField($searchfor['description']), "LDAPHeader");
		$fields->push(new LiteralField("LDAPDescription", 
		                               "Enter the value of the attribute as defined in the LDAP server"));
		$fields->push(new TextField("LDAPAttribute", $searchfor['description']), "LDAPAttribute");
	}


	/**
	 * Can the current user edit the given member?
	 *
	 * Only the user itself or an administrator can edit an user account.
	 *
	 * @return bool Returns TRUE if this member can be edited, FALSE otherwise
	 */
	function canEdit() {
		if($this->owner->ID == Member::currentUserID()) {
			return true;
		}

		$member = Member::currentUser();
		if($member) {
			return $member->isAdmin();
		}

		return false;
	}
}



/**
 * Validator of the decorator for the member class to support OpenID
 * authentication
 */
class LDAPAuthenticatedRole_Validator extends Extension {

	/**
	 * Server-side validation
	 *
	 * This method checks if the entered identity URL is unique.
	 *
	 * @param array $data User submitted data
	 * @param Form $form The used form
	 * @return bool Returns TRUE if the submitted data is valid, otherwise
	 *              FALSE.
	 */
	function updatePHP(array $data, Form &$form) {
		if(!isset($data['LDAPAttribute']) || strlen(trim($data['LDAPAttribute'])) == 0)
			return true;

		$member = DataObject::get_one('Member',
			"LDAPAttribute = '". Convert::raw2sql($data['LDAPAttribute']) ."'");

		// if we are in a complex table field popup, use ctf[childID], else use
		// ID
		$id = null;
		if(isset($_REQUEST['ctf']['childID'])) {
			$id = $_REQUEST['ctf']['childID'];
		} elseif(isset($_REQUEST['ID'])) {
			$id = $_REQUEST['ID'];
		}

		if(is_object($member) && $member->ID != $id) {
			$field = $form->dataFieldByName('LDAPAttribute');
			$this->owner->validationError($field->id(),
				"There already exists a member with this LDAP attribute",
				"required");
			return false;
		}

		return true;
	}
}
