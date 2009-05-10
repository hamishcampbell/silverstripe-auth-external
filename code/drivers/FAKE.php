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
        
