<?php
/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */
namespace Piwik\Plugins\LoginHttpAuth;

use Piwik\AuthResult;
use Piwik\DB;
use Piwik\Access;
use Piwik\Date;
use Piwik\Plugins\Login;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Plugins\UsersManager\API as UsersManagerAPI;
use Piwik\Plugins\SitesManager\API as SitesManagerAPI;

class Auth implements \Piwik\Auth
{
    /**
     * @var Model
     */
    private $userModel;

    /**
     * @var Auth
     */
    private $fallbackAuth;

    /**
     * Constructor.
     *
     * @param Model|null $userModel
     */
    public function __construct(Model $userModel = null)
    {
        if ($userModel === null) {
            $userModel = new Model();
        }

        $this->userModel = $userModel;
        $this->fallbackAuth = new \Piwik\Plugins\Login\Auth();
    }

    /**
     * Authentication module's name
     *
     * @return string
     */
    public function getName()
    {
        return 'LoginHttpAuth';
    }

    /**
     * Authenticates user
     *
     * @return \Piwik\AuthResult
     */
    public function authenticate()
    {
        $httpLogin = $this->getHttpAuthLogin();
        if (!empty($httpLogin)) {
            $user = $this->userModel->getUser($httpLogin);

            if(empty($user)) {
		$user = $this->createUserFromHttpAuthUser($httpLogin);
            }

            $code = !empty($user['superuser_access']) ? AuthResult::SUCCESS_SUPERUSER_AUTH_CODE : AuthResult::SUCCESS;
            return new AuthResult($code, $user['login'], $user['token_auth']);

        }
        return $this->fallbackAuth->authenticate();
    }

    protected function createUserFromHttpAuthUser($httpLogin)
    {	

	    $user = array(
			    'login' => $httpLogin,
			    'password' => md5('NO_LOCAL_AUTH'),
			    'email' => $httpLogin . '@uvm.edu'
			 );


	    $usersManagerApi = UsersManagerAPI::getInstance();
	    $token_auth = $usersManagerApi->createTokenAuth($user['login']);
	    $this->userModel->addUser($user['login'], $user['password'], $user['email'], $user['login'], $token_auth, Date::now()->getDatetime());	

	    $new_user = $this->userModel->getUser($httpLogin);
		
	    if (!empty($new_user)){

		    // Set new user view access.  By default, we are making it so they can view all sites.
		    // TODO: add settings/config option for this.
		    $default_site_ids = $this->getSiteIDs();

		    $default_role = 'view'; 
		    Access::doAsSuperUser(function () use ($default_site_ids,$default_role, $new_user) {
				    $usersManagerApi = UsersManagerAPI::getInstance();
				    $usersManagerApi->setUserAccess($new_user['login'], $default_role, $default_site_ids);
				    });

		    return $new_user;
	    }
		
    }

	protected function getSiteIDs(){

		$site_ids = Access::doAsSuperUser(function () {
				$sitesManagerApi = SitesManagerAPI::getInstance();
				return $sitesManagerApi->getAllSitesId();
				});
		return $site_ids;
	}


    protected function getHttpAuthLogin()
    {
        $httpLogin = false;
        if (isset($_SERVER['PHP_AUTH_USER'])) {
            $httpLogin = $_SERVER['PHP_AUTH_USER'];
        } elseif (isset($_SERVER['HTTP_AUTH_USER'])) {
           $httpLogin = $_SERVER['HTTP_AUTH_USER'];
        } elseif (isset($_ENV['AUTH_USER'])) {
            $httpLogin = $_ENV['AUTH_USER'];
        } elseif (isset($_SERVER['REMOTE_USER'])) {
            $httpLogin = $_SERVER['REMOTE_USER'];
        } elseif (isset($_ENV['REDIRECT_REMOTE_USER'])) {
            $httpLogin = $_ENV['REDIRECT_REMOTE_USER'];
        }
        return $httpLogin;
    }

    public function setTokenAuth($token_auth)
    {
        $this->fallbackAuth->setTokenAuth($token_auth);
    }

    public function getLogin()
    {
        $this->fallbackAuth->getLogin();
    }

    public function getTokenAuthSecret()
    {
        return $this->fallbackAuth->getTokenAuthSecret();
    }

    public function setLogin($login)
    {
        $this->fallbackAuth->setLogin($login);
    }

    public function setPassword($password)
    {
        $this->fallbackAuth->setPassword($password);
    }

    public function setPasswordHash($passwordHash)
    {
        $this->fallbackAuth->setPasswordHash($passwordHash);
    }
}

