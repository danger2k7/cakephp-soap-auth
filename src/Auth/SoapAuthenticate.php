<?php
/**
 * @author Bogdan SOOS <bogdan.soos@dynweb.org>
 * @created 08/03/2017 20:54
 * @version 0.1
 * @license MIT
 */
namespace Dynweb\SoapAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Http\ServerRequest;
use Cake\Http\Response;
use Zend\Diactoros\Stream;

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
     * Parsed token.
     *
     * @var string|array|null
     */
    protected $_token;

    /**
     * Payload data.
     *
     * @var object|null
     */
    protected $_payload;

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
            'soapHeader' => [
                'username' => 'username',
                'password' => 'password',
            ],
            'fields' => [
                'username' => 'username',
                'password' => 'password',
            ],
            'queryDatasource' => true,
            'unauthenticatedException' => '\SoapFault',
            'key' => null,
        ]);

        parent::__construct($registry, $config);
    }

    /**
     * Authenticate a user based on the request information.
     *
     * @param \Cake\Http\ServerRequest $request Request to get authentication information from.
     * @param \Cake\Http\Response $response A response object that can have headers added.
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
        $payload = $this->getPayload($request);
        if (empty($payload)) {
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
     * Get payload data.
     *
     * @param \Cake\Http\ServerRequest|null $request Request instance or null
     *
     * @return object|null|array Payload object on success, null on failurec
     */
    public function getPayload($request = null)
    {
        if (!$request) {
            return $this->_payload;
        }
        $payload = null;
        $token = $this->getToken($request);

        if ( $token && is_array($token)){
            $payload = $token;
        }

        return $this->_payload = $payload;
    }

    /**
     * Get token from header or query string.
     *
     * @param \Cake\Http\ServerRequest|null $request Request object.
     *
     * @return string|null Token string if found else null.
     */
    public function getToken($request = null)
    {
        $config = $this->getConfig();

        if (!$request) {
            return $this->_token;
        }

        /** @var \DOMDocument $dom */
        $dom = $request->input('Cake\Utility\Xml::build', ['return' => 'domdocument']);

        if (count($dom->getElementsByTagName($config['soapHeader']['username'])) > 0){
            $this->_username = $dom->getElementsByTagName($config['soapHeader']['username'])[0]->nodeValue;

        }

        if (count($dom->getElementsByTagName($config['soapHeader']['password'])) > 0){
            $this->_password = $dom->getElementsByTagName($config['soapHeader']['password'])[0]->nodeValue;

        }
        if (!empty($this->_username) && !empty($this->_password)){
            $this->_token = [
                $config['fields']['username'] => $this->_username,
                $config['fields']['password'] => $this->_password
            ];
        }

        return $this->_token;
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
     * @param \Cake\Http\Response $response A response object.
     *
     * @throws \Cake\Network\Exception\UnauthorizedException Or any other
     *   configured exception.
     *
     * @return \Cake\Http\Response|void
     */
    public function unauthenticated(ServerRequest $request, Response $response)
    {

        /** @var Response $response */
        $response->withType('text/xml');
        $dom = ('
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
           <SOAP-ENV:Body>
              <SOAP-ENV:Fault>
                 <faultcode>UNAUTHORIZED</faultcode>
                 <faultstring>' . __('You are not authorized to access that location') . '</faultstring>
              </SOAP-ENV:Fault>
           </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
        ');

        $responseBody = new Stream('php://memory', 'rw');
        $responseBody->write($dom);
        $responseBody->rewind();
        $response = $response->withBody($responseBody);

        return $response;
    }
}
