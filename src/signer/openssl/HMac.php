<?php

namespace tuanlq11\token\signer\openssl;
/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 10:30 AM
 */
abstract class HMac
{

  abstract public function getAlg();

  /**
   * Generate sign
   *
   * @param $input
   * @param $key
   * @return string
   */
  public function sign($input, $key)
  {
    return hash_hmac($this->getAlg(), $input, $key);
  }

  /**
   * Verify input data by sign
   * @param $key
   * @param $signed
   * @param $input
   * @return bool
   */
  public function verify($key, $signed, $input) {
    $sign = $this->sign($input, $key);

    if(version_compare(PHP_VERSION, '5.6.0', '>=')) {
      return hash_equals($signed, $sign);
    }

    return $this->timingSafeEquals($signed, $sign);
  }

  /**
   * Compare two sign key
   * @param $signature
   * @param $signedInput
   * @return bool
   */
  public function timingSafeEquals($signature, $signedInput) {
    $signatureLength   = strlen($signature);
    $signedInputLength = strlen($signedInput);
    $result            = 0;

    if ($signedInputLength != $signatureLength) {
      return false;
    }

    for ($i = 0; $i < $signedInputLength; $i++) {
      $result |= (ord($signature[$i]) ^ ord($signedInput[$i]));
    }

    return $result === 0;
  }
}