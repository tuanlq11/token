<?php
namespace tuanlq11\token\signer;

use InvalidArgumentException;
use tuanlq11\token\Signer\OpenSSL\HMac;

/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 10:46 AM
 */
class Signer
{

  /** @var  HMac */
  protected $encoder;

  /** @var  array */
  protected $header;

  /** @var  array */
  protected $payload;

  /** @var  string */
  protected $signature;

  /** @var  string */
  protected $salt;

  /**
   * Return new signer class
   */
  protected function getSigner($alg)
  {
    $signerStr = sprintf('tuanlq11\\token\\signer\\openssl\\%s', strtoupper($alg));
    if (class_exists($signerStr)) {
      return new $signerStr;
    }

    throw new InvalidArgumentException(sprintf('Algorithm "%s" is invalid!', $alg));
  }

  /**
   * Set property Header
   * [alg => HS256|HS384|HS512]
   * @param $header
   */
  public function setHeader($header)
  {
    $this->header = $header;
    $alg = $header['alg'];

    $this->encoder = $this->getSigner($alg);
  }

  /**
   * @return array
   */
  public function getPayload()
  {
    return $this->payload;
  }

  /**
   * @param array $payload
   */
  public function setPayload($payload)
  {
    $this->payload = $payload;
  }

  /**
   * Get Property Header
   *
   */
  public function getHeader()
  {
    return $this->header;
  }

  /**
   * @return string
   */
  public function getSignature()
  {
    return $this->signature;
  }

  /**
   * @param string $signature
   */
  public function setSignature($signature)
  {
    $this->signature = $signature;
  }

  /**
   * @param $key
   * @return string
   */
  public function sign($key)
  {
    $this->signature = $this->encoder->sign(json_encode($this->payload), $key);
    return $this->signature;
  }

  /**
   * Export token after sign
   * @return string
   */
  public function getTokenString()
  {
    $token = sprintf('%s.%s.%s',
      base64_encode(json_encode($this->getHeader())),
      base64_encode(json_encode($this->getPayload())),
      base64_encode($this->getSignature())
    );

    return $token;
  }

  /**
   * @param $token
   * @param $secret
   * @return bool|mixed
   */
  public function verify($token, $secret)
  {
    $parts = explode('.', $token);

    if (count($parts) != 3) {
      return false;
    }

    $header = json_decode(base64_decode($parts[0]), true);
    $payloadJSON = base64_decode($parts[1]);
    $payload = json_decode($payloadJSON, true);
    $signInput = base64_decode($parts[2]);

    if (!isset($header['alg'])) {
      return false;
    }
    $alg = $header['alg'];
    $encoder = $this->getSigner($alg);

    if ($encoder->verify($secret, $signInput, $payloadJSON) && $payload['exp'] > time()) {
      return $payload;
    }

    return false;
  }
}