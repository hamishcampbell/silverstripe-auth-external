<?php

/**
 * External authentication decorator
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 * @author Silverstripe team; I copied lots of code from them
 */

/**
 * Decorator for the member class to support authentication
 *
 * This class adds the needed fields to the default member class to support
 * authentication via the external authentication method.
 */
class ExternalAuthenticatedRole extends DataExtension {

    /**
     * Define extra database fields
     *
     * Returns a map where the keys are db, has_one, etc, and the values are
     * additional fields/relations to be defined
     *
     * @return array Returns a map where the keys are db, has_one, etc, and
     *               the values are additional fields/relations to be defined
     */
    function extraStatics($class = null, $extension = null) {
        return array(
            'db' => array('External_Anchor' => 'Varchar(255)', 
                          'External_SourceID' => 'Varchar(50)'),
            'has_one' => array(),
            'defaults' => array('External_Anchor' => null,
                                'External_SourceID' => null),
            'indexes' => array('External_Anchor' => true)
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
    function updateCMSFields(FieldList $fields) {
    	// let make sure, this runs only once (because member and dataobject both extend updateCMSFields
    	// 	making it run twice!)
    	$cp = $fields->fieldByName('Root');
    	if ($cp && $cp->fieldByName('ExternalAuthentication')) return;

    	$sources    = ExternalAuthenticator::getIDandNames();
        $sources    = array_merge(array("" => "-"), $sources);
		$fields->findOrMakeTab('Root.ExternalAuthentication', _t('ExternalAuthenticator.Title'));
        $fields->addFieldToTab('Root.ExternalAuthentication',
        						new HeaderField('External_Header', _t('ExternalAuthenticator.ModFormHead','ID for external authentication source')));
        $fields->addFieldToTab('Root.ExternalAuthentication', 
                               new LiteralField('ExternalDescription',_t('ExternalAuthenticator.EnterUser',
                                                'Enter the user id and authentication source for this user'))
                              );
        $fields->addFieldToTab('Root.ExternalAuthentication', 
                               new DropdownField('External_SourceID', _t('ExternalAuthenticator.Sources'),
                                                 $sources));
        $fields->addFieldToTab('Root.ExternalAuthentication',
                               new TextField('External_Anchor', _t('ExternalAuthenticator.EnterNewId',
                                                                   'ID to be used with this source')));
    }


    /**
     * Can the current user edit the given member?
     *
     * Only the user itself or an administrator can edit an user account.
     *
     * @return bool Returns TRUE if this member can be edited, FALSE otherwise
     */
    function canEdit($member = null) {
        if($this->owner->ID == Member::currentUserID()) {
            return true;
        }

        $member = Member::currentUser();
        if($member) {
            return $member->inGroup('Administrators');
        }

        return false;
    }
}



/**
 * Validator of the decorator for the member class to support OpenID
 * authentication
 */
class ExternalAuthenticatedRole_Validator extends Extension {

    /**
     * Server-side validation
     *
     * This method checks if the entered account identifier is unique.
     *
     * @param array $data User submitted data
     * @param Form $form The used form
     * @return bool Returns TRUE if the submitted data is valid, otherwise
     *              FALSE.
     */
    function updatePHP(array $data, Form &$form) {
        if (!isset($data['External_Anchor']) || strlen(trim($data['External_Anchor'])) == 0 || 
            !isset($data['External_SourceID']) || strlen($data['External_SourceID']) == 0)
            return true;

        $member = DataObject::get_one('Member',
                  '"External_Anchor" = \''. 
                  Convert::raw2sql($data['External_Anchor']) .
                  '\' AND "External_SourceID" = \'' . 
                  Convert::raw2sql($data['External_SourceID']) .'\'');

        // if we are in a complex table field popup, use ctf[childID], else use
        // ID
        $id = null;
        if (isset($_REQUEST['ctf']['childID'])) {
            $id = $_REQUEST['ctf']['childID'];
        } elseif(isset($_REQUEST['ID'])) {
            $id = $_REQUEST['ID'];
        } elseif(isset($form->getRecord()->ID)) {
            $id = $form->getRecord()->ID;
        }

        if(is_object($member) && $member->ID != $id) {
            $field = $form->Fields()->dataFieldByName('External_Anchor');
            $this->owner->validationError($field->id(),
                _t('ExternalAuthenticator.UserExists', 'There already exists a member with this account name'),
                'required');
            return false;
        }

        return true;
    }
}
