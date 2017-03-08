<?php
/**
 * This file is part of the Pilotage package.
 *
 * @author Bogdan SOOS <bogdan.soos@external.engie.com>
 * @created 08/03/2017 20:54
 * @version 1.0
 * @license All rights reserved
 */
namespace Dynweb\SoapAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Http\ServerRequest;
use Cake\Log\Log;
use Cake\Network\Request;
use Cake\Network\Response;


/**
 * An authentication adapter for authenticating using Request/SoapHeaders.
 *
 * ```
 *  $this->Auth->config('authenticate', [
 *      'Dynweb\SoapAuth.Soap' => [
 *          'userModel' => 'Users',
 *          'fields' => [
 *              'username' => 'username',
 *              'password' => 'password',
 *          ],
 *      ]
 *  ]);
 * ```
 *
 * @copyright 2017 Bogdan SOOS
 * @license MIT

 */
class SoapAuthenticate extends BaseAuthenticate
{

    /**
     * Parsed username.
     *
     * @var string|null
     */
    protected $_username;

    /**
     * Parsed password.
     *
     * @var string|null
     */
    protected $_password;

    /**
     * Payload data.
     *
     * @var object|null
     */
    protected $_payload;
    /**
     * Exception.
     *
     * @var \Exception
     */
    protected $_error;

    /**
     * SoapAuthenticate constructor.
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry
     *   used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, $config)
    {
        $this->setConfig([
           'userModel' => 'Users',
           'fields' => [
               'username' => 'username',
               'password' => 'password',
           ],
           'queryDatasource' => true,
           'unauthenticatedException' => '\Cake\Network\Exception\UnauthorizedException',
           'key' => null,
        ]);

        parent::__construct($registry, $config);
    }

    /**
     * Authenticate a user based on the request information.
     *
     * @param \Cake\Http\ServerRequest $request Request to get authentication information from.
     * @param \Cake\Network\Response $response A response object that can have headers added.
     * @return mixed Either false on failure, or an array of user data on success.
     */
    public function authenticate(ServerRequest $request, Response $response)
    {
        return $this->getUser($request);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     *
     * @return bool|array User record array or false on failure.
     */
    public function getUser(ServerRequest $request)
    {
        $login = $this->getUsernameAndPassword($request);
        if (empty($login)) {
            return false;
        }

        $user = $this->_findUser($this->_username, $this->_password);

        if (!$user) {
            return false;
        }
        unset($user[$this->getConfig('fields.password')]);

        return $user;
    }


    /**
     * Get token from header or query string.
     *
     * @param \Cake\Http\ServerRequest|null $request Request object.
     *
     * @return array|null Token string if found else null.
     */
    public function getUsernameAndPassword(ServerRequest $request = null)
    {
        $config = $this->getConfig();
        if (!$request) {
            return null;
        }

        Log::debug($request->getHeaders());

        $this->_username = $request->getHeader($config['fields']['username']);
        $this->_password = $request->getHeader($config['fields']['password']);
        if ($this->_username && $this->_password) {
            return [
                $this->getConfig('fields.username') => $this->_username,
                $this->getConfig('fields.password') => $this->_password,
            ];
        }

        return null;
    }


    /**
     * Handles an unauthenticated access attempt. Depending on value of config
     * `unauthenticatedException` either throws the specified exception or returns
     * null.
     *
     * @param \Cake\Http\ServerRequest $request A request object.
     * @param \Cake\Network\Response $response A response object.
     *
     * @throws \Cake\Network\Exception\UnauthorizedException Or any other
     *   configured exception.
     *
     * @return void
     */
    public function unauthenticated(ServerRequest $request, Response $response)
    {
        $this->getConfig();
        if (!$this->getConfig('unauthenticatedException')) {
            return;
        }
        $message = $this->_error ? $this->_error->getMessage() : $this->_registry->Auth->_config['authError'];
        $exceptionClass = $this->getConfig('unauthenticatedException');
        $exception = new $exceptionClass($message);

        throw $exception;
    }
}
