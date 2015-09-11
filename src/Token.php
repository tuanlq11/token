<?php

namespace tuanlq11\token;
use Namshi\JOSE\JWS;

/**
 * Class Token
 * @package tuanlq11\token
 */
class Token
{
  protected $jws;

  protected $jwt;

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
//    $this->jws = new JWS();
  }

}