<?php
/**
 * Test the external authentication logon.
 * We only test against a SilverStripe Backend
 *
 * Based on the Sapphire Security Unittest
 *
 * @author Roel Gloudemans <roel@gloudemans.info>
 **/
class ExternalAuthenticatorTest extends FunctionalTest {
	static $fixture_file = 'auth_external/tests/AuthExternal.yml';
	
	protected $autoFollowRedirection = false;
	
	protected $priorAuthenticators = array();
	
	protected $priorDefaultAuthenticator = null;
	
	function setUp() {
            // This test assumes that MemberAuthenticator is present and the default
            $this->priorAuthenticators = Authenticator::get_authenticators();
            $this->priorDefaultAuthenticator = Authenticator::get_default_authenticator();

            //Authenticator::register('MemberAuthenticator');
            Authenticator::register_authenticator('ExternalAuthenticator');
            Authenticator::set_default_authenticator('ExternalAuthenticator');
		
            //Create the sources in this order. Switching them around would mean that
            //all tests use the fake driver because this always succeeds and auto create
            //is on
            ExternalAuthenticator::createSource('sstripe_unittest','SSTRIPE','SilverStripe');
            ExternalAuthenticator::createSource('fake_unittest','FAKE','Fake Source');
		      
            ExternalAuthenticator::setAuthSequential(true);
            ExternalAuthenticator::setAuthSSLock('sstripe_unittest',true);
            ExternalAuthenticator::setAuthSSLock('fake_unittest',false);
            ExternalAuthenticator::setAutoAdd('fake_unittest', 'mygroup');
            ExternalAuthenticator::setDefaultDomain('fake_unittest', 'silverstripe.com');

            ExternalAuthenticator::setAuthDebug(false);
            ExternalAuthenticator::setAuditLogFile(false);
            ExternalAuthenticator::setAuditLogSStripe(true);

            parent::setUp();
	}
	
	function tearDown() {
		// Restore selected authenticator
		
		// MemberAuthenticator might not actually be present
		if(!in_array('ExternalAuthenticator', $this->priorAuthenticators)) {
			Authenticator::unregister('ExternalAuthenticator');
		}
		Authenticator::set_default_authenticator($this->priorDefaultAuthenticator);
		
		parent::tearDown();
	}
	
	
	function testRepeatedLoginAttemptsLockingPeopleOut() {
		Member::lock_out_after_incorrect_logins(5);
		
		/* LOG IN WITH A BAD PASSWORD 7 TIMES */

		for($i=1;$i<=7;$i++) {
			$this->doTestLoginForm('testing' , 'incorrectpassword');
			$member = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'test'));
			
			/* THE FIRST 4 TIMES, THE MEMBER SHOULDN'T BE LOCKED OUT */
			if($i < 5) {
				$this->assertNull($member->LockedOutUntil);
				$this->assertTrue(false !== stripos($this->loginErrorMessage(), _t('ExternalAuthenticator.Failed')));
			}
			
			/* AFTER THAT THE USER IS LOCKED OUT FOR 15 MINUTES */

			//(we check for at least 14 minutes because we don't want a slow running test to report a failure.)
			else {
				$this->assertGreaterThan(time() + 14*60, strtotime($member->LockedOutUntil));
			}
			
			if($i > 5) {
				$this->assertTrue(false !== stripos($this->loginErrorMessage(), _t('ExternalAuthenticator.Failed')));
			}
		}
		
		/* THE USER CAN'T LOG IN NOW, EVEN IF THEY GET THE RIGHT PASSWORD */
		
		$this->doTestLoginForm('testing' , 'test1');
		$this->assertNull($this->session()->inst_get('loggedInAs'));
		
		/* BUT, IF TIME PASSES, THEY CAN LOG IN */

		// (We fake this by re-setting LockedOutUntil)
		$member = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'test'));
		$member->LockedOutUntil = date('Y-m-d H:i:s', time() - 30);
		$member->write();
		
		$this->doTestLoginForm('testing' , 'test1');
		$this->assertEquals($this->session()->inst_get('loggedInAs'), $member->ID);
		
		// Log the user out
		$this->session()->inst_set('loggedInAs', null);

		/* NOW THAT THE LOCK-OUT HAS EXPIRED, CHECK THAT WE ARE ALLOWED 4 FAILED ATTEMPTS BEFORE LOGGING IN */

		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$this->assertNull($this->session()->inst_get('loggedInAs'));
		$this->assertTrue(false !== stripos($this->loginErrorMessage(), _t('ExternalAuthenticator.Failed')));
		
		$this->doTestLoginForm('testing' , 'test1');
		$this->assertEquals($this->session()->inst_get('loggedInAs'), $member->ID);
	}
	
	function testAlternatingRepeatedLoginAttempts() {
		Member::lock_out_after_incorrect_logins(3);
		
		// ATTEMPTING LOG-IN TWICE WITH ONE ACCOUNT AND TWICE WITH ANOTHER SHOULDN'T LOCK ANYBODY OUT

		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$this->doTestLoginForm('testing' , 'incorrectpassword');

		$this->doTestLoginForm('anothertest' , 'incorrectpassword');
		$this->doTestLoginForm('anothertest' , 'incorrectpassword');
		
		$member1 = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'test'));
		$member2 = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'anothertest'));
		
		$this->assertNull($member1->LockedOutUntil);
		$this->assertNull($member2->LockedOutUntil);
		
		// BUT, DOING AN ADDITIONAL LOG-IN WITH EITHER OF THEM WILL LOCK OUT, SINCE THAT IS THE 3RD FAILURE IN THIS SESSION

		$this->doTestLoginForm('testing' , 'incorrectpassword');
		$member1 = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'test'));
		$this->assertNotNull($member1->LockedOutUntil);

		$this->doTestLoginForm('anothertest' , 'incorrectpassword');
		$member2 = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'anothertest'));
		$this->assertNotNull($member2->LockedOutUntil);
	}
	
	
	function testSuccessfulLoginAttempts() {
		$this->doTestLoginForm('testing', 'test1');
		
		$member = DataObject::get_by_id("Member", $this->idFromFixture('Member', 'test'));
	    $this->assertEquals($this->session()->inst_get('loggedInAs'), $member->ID);
	}
	
	/**
	 * Test auto creation of user accounts
	 **/
	function testAutoCreateAccount() {
        $this->doTestLoginForm('idonotexist', 'blurp');
        
        //Useraccount should now exist
        $member = DataObject::get_one('Member', "Email = 'idonotexist@silverstripe.com'");
        $this->assertEquals($this->session()->inst_get('loggedInAs'), $member->ID);
        
        $attempt = DataObject::get_one('LoginAttempt', "Email = 'idonotexist@fake_unittest'");
		$this->assertTrue(is_object($attempt));
	}
		

	/**
	 * Execute a log-in form using Director::test().
	 * Helper method for the tests above
	 */
	function doTestLoginForm($anchor, $password) {
		$this->session()->inst_set('BackURL', 'test/link');
		$this->get('Security/login');
		
		return $this->submitForm(
			"ExternalLoginForm_LoginForm", 
			null,
			array(
				'External_Anchor' => $anchor, 
				'Password' => $password, 
				'AuthenticationMethod' => 'ExternalAuthenticator',
				'action_dologin' => 1,
			)
		); 
	}
	

	/**
	 * Get the error message on the login form
	 */
	function loginErrorMessage() {
		return $this->session()->inst_get('FormInfo.ExternalLoginForm_LoginForm.formError.message');
	}	
	
}
?>
