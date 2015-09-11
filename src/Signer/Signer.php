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

  /**
   * Return new signer class
   */
  protected function getSigner($alg)
  {
    $signerStr = sprintf('tuanlq11\\token\\Signer\\OpenSSL\\%s', strtoupper($alg));
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
    $this->signature = $this->encoder->sign($this->payload, $key);
    return $this->signature;
  }

  public function getTokenString() {
    $token = sprintf('%s.%s.%s',
      base64_encode(json_encode($this->getHeader())),
      base64_encode(json_encode($this->getPayload())),
      base64_encode(json_encode($this->getSignature()))
    );

    return $token;
  }
}