<?php

namespace tuanlq11\token;
use App\User;
use tuanlq11\token\signer\Signer;

/**
 * Class Token
 * @author tuanlq11
 * @package tuanlq11\token
 */
class Token
{
  /** @var Signer  */
  protected $jws;

  /** @var  JWT */
  protected $jwt;

  /** @var  String */
  protected $header;

  /** @var  String */
  protected $alg;

  /** @var  String */
  protected $identify;

  /** @var  String */
  protected $secret;

  /** @var  Integer */
  protected $ttl;

  function __construct()
  {
    $this->alg = \Config::get('token.alg');
    $this->identify = \Config::get('token.identify');
    $this->header = ['alg' => $this->alg];
    $this->secret = \Config::get('token.secret');
    $this->ttl = \Config::get('token.ttl');

    $this->jws = new Signer();

    return $this;
  }

  /**
   * Generate new salt
   */
  protected function generateSalt() {
    return hash_hmac('sha256', str_random(32) . time() . $this->secret, str_random());
  }

  /**
   * Authenticate Credentials and generate token
   * @param $credentials
   * @return bool
   */
  public function attempt($credentials)
  {
    if (!\Auth::once($credentials)) {
      return false;
    }

    $user = User::whereEmail($credentials[$this->identify])->first();

    $payload = [
      'uid' => $user->{$this->identify},
      'exp' => time() + $this->ttl,
      'domain' => \Request::root(),
      'salt' => $this->generateSalt()
    ];

    return $this->toToken($payload);
  }

  /**
   * Authenticate token and export User from token
   * @param $token
   * @return bool|array
   */
  public function fromToken($token) {
    return $this->jws->verify($token, $this->secret);;
  }

  /**
   * Generate token from payload
   * @param $payload
   * @return string
   */
  public function toToken($payload) {
    $this->jws->setHeader($this->header);
    $this->jws->setPayload($payload);
    $this->jws->sign($this->secret);

    return $this->jws->getTokenString();
  }

}