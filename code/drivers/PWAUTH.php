<?php
/**
 * PWAuth-Driver to authenticate against system accounts
 *
 * requires pwauth from https://code.google.com/p/pwauth/
 *
 * @author Nico Haase <nico@nicohaase.de>
 */
 
class PWAuth_Authenticator {

    /**
     * path to pwauth
     */   
    private $pwauthPath = '/usr/local/sbin/pwauth';
                                                         
    /**
     * Tries to logon against pwauth with given id and password
     *
     * @access public
     *
     * @param  string $source Authentication source to be used 
     * @param  string $external_uid    The ID entered
     * @param  string $external_passwd The password of the user
     *
     * @return boolean  True if the authentication was a success, false 
     *                  otherwise
     */
    public function Authenticate($source, $external_uid, $external_passwd) {
        // Sourcecode borrowed at i http://www.mediawiki.org/wiki/Extension:PwAuthPlugin
		// Start
		$handle = popen($this->pwauthPath, 'w');
		if ($handle === FALSE) {
				die("Error opening pipe to pwauth");
				return false;
		}
		if (fwrite($handle, "$external_uid\n$external_passwd\n") === FALSE) {
				die("Error writing to pwauth pipe");
				return false;
		}

		# Is the password valid?
		$result = pclose( $handle );
		// End from MediaWiki
		if ($result==0) {
			// Login okay, read data from /etc/passwd
			$etcPasswd = file('/etc/passwd' );
			foreach($etcPasswd as $singleLine ) {
				if (substr($singleLine, 0, strlen($external_uid ) + 1 ) == $external_uid . ':' ) {
					$explodedLine = explode(':', $singleLine );
					$userData = explode(',', $explodedLine[4] );
					$name = $userData[0];
					$firstName = substr($name, 0, strrpos($name, ' ' ) );
					$lastName = substr($name, strrpos($name, ' ' ) + 1 );
					$return = array();
					$return['firstname'] = $firstName;
					$return['surname'] = $lastName;
					return $return;
				}
			}
		}
		return false;
    }
}
?>
