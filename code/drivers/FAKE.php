<?php
/**
 * Fake driver for authentication
 * Always accepts login attempts
 *
 * USAGE FOR DEVELOPMENT AND TESTING PURPOSES ONLY
 *
 * @author Roel Gloudemans <roel@gloudemans.info> 
 */
 
class FAKE_Authenticator {
    /**
     * Tries to find the anchor for a given mail address and source
     *
     * @access public
     *
     * @param string $source          The Authentication source to be used
     * @param string $mailaddr        The mail address entered
     *
     * @return mixed    Anchor as string or false if not found
     **/
    public function getAnchor($source, $mailaddr) {
        ExternalAuthenticator::AuthLog($mailaddr.'.fake - Anchor lookup not supported by source ' . $source);
        return false;
    }
        
    /**
     * Logs the user on
     *
     * @access public
     *
     * @param  string $source Authentication source to be used 
     * @param  string $external_uid    The ID entered
     * @param  string $external_passwd The password of the user
     *
     * @return boolean  True
     */
    public function Authenticate($RAW_source, $RAW_external_anchor, $RAW_external_passwd) {
        return true;
    }
}
        
