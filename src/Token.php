<?php

namespace tuanlq11\token;
use App\User;
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

  /** @var  String */
  protected $alg;

  /** @var  String */
  protected $identify;

  /** @var  String */
  protected $secret;

  function __construct()
  {
    $this->alg = \Config::get('token.alg');
    $this->identify = \Config::get('token.identify');
    $this->header = ['alg' => $this->alg];
    $this->secret = \Config::get('token.secret');

    $this->jws = new JWS($this->header);

    return $this;
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

    $user = User::whereEmail($credentials[$this->identify]);

    $payload = ['uid' => $user->{$this->identify}, 'alg' => \Config::get('token.')];

    return $this->toToken($payload, $user->password);
  }

  public function fromToken() {

  }

  public function toToken($payload, $password = null) {

    $sign = $this->jws->setPayload($payload)->sign($this->secret, $password);

    echo $sign; exit;

  }

}