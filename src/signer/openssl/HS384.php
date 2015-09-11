<?php

namespace tuanlq11\token\signer\openssl;
/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 10:45 AM
 */
class HS384 extends HMac
{
  public function getAlg()
  {
    return 'sha384';
  }

}