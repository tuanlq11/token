<?php

namespace tuanlq11\token;
use Namshi\JOSE\JWS;
use Namshi\JOSE\JWT;

/**
 * Class Token
 * @package tuanlq11\token
 */
class Token
{
  /** @var  JWS */
  protected $jws;

  /** @var  JWT */
  protected $jwt;

  /** @var  String */
  protected $header;

  function __construct()
  {
    $header = ['alg' => \Config::get('token')];
    $this->jws = new JWS($header);
  }

  /**
   * @param $credentials
   * @return bool
   */
  public function attempt($credentials)
  {
    if (!\Auth::once($credentials)) {
      return false;
    }

    return $this->toToken($credentials);
  }

  public function fromToken() {

  }

  public function toToken($credentials) {
    $key = \Config::get('token', 'default');

    echo $this->jws->getSignature();

  }

}