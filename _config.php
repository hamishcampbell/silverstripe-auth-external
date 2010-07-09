<?php
/**
 * See the docs directory for configuration examples
 **/
Authenticator::register_authenticator('ExternalAuthenticator');
ExternalAuthenticator::setValidAddress('silverstripe','127.0.0.1');

