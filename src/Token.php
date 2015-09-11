<?php

namespace tuanlq11\token;

use App\User;
use Carbon\Carbon;
use tuanlq11\token\signer\Signer;

/**
 * Class Token
 * @author tuanlq11
 * @package tuanlq11\token
 */
class Token
{
  /** @var Signer */
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

  const PREFIX_CACHE_KEY = 'tuanlq11.token.blacklist.';

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
  protected function generateSalt($uid)
  {
    return md5($uid) . hash_hmac('sha256', str_random(32) . time() . $this->secret, str_random());
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
    $uid = $user->{$this->identify};

    $payload = $this->getPayload($uid, time() + $this->ttl);

    return $this->toToken($payload);
  }

  /**
   * Generate new Payload
   * @param $uid
   * @param $exp
   * @return array
   */
  protected function getPayload($uid, $exp)
  {
    $payload = [
      'uid' => $uid,
      'exp' => $exp,
      'domain' => \Request::root(),
      'salt' => $this->generateSalt($uid)
    ];

    return $payload;
  }

  /**
   * @param $token
   * @return bool|User
   */
  public function fromToken($token)
  {
    $key = self::PREFIX_CACHE_KEY . $token;

    if (\Cache::has($key)) {
      return false;
    }

    if (($payload = $this->jws->verify($token, $this->secret))) {
      return User::where($this->identify, '=', $payload['uid'])->first();
    }

    return false;
  }

  /**
   * @param $token
   * @return bool
   */
  public function refresh($token)
  {
    if ($user = $this->fromToken($token)) {
      $uid = $user->{$this->identify};
      $payload = $this->getPayload($uid, time() + $this->ttl);
      $newToken = $this->toToken($payload);

      // Blacklist
      $key = self::PREFIX_CACHE_KEY . $token;
      \Cache::put($key, [], Carbon::now()->addSecond($this->ttl));
      // End

      return $newToken;
    }

    return false;
  }

  /**
   * Generate token from payload
   * @param $payload
   * @return string
   */
  public function toToken($payload)
  {
    $this->jws->setHeader($this->header);
    $this->jws->setPayload($payload);
    $this->jws->sign($this->secret);

    return $this->jws->getTokenString();
  }

}