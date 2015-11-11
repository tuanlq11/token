<?php
namespace tuanlq11\token\signer;

use InvalidArgumentException;
use tuanlq11\token\Payload;
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

    /** @var  Payload */
    protected $payload;

    /** @var  bool */
    private $signed;

    /** @var  string */
    protected $signature;

    /**
     * @param $token
     * @return $this
     */
    public static function getInstance($token)
    {
        return (new Signer())->load($token);
    }

    /**
     * @return HMac
     */
    public function getEncoder()
    {
        return $this->encoder;
    }

    /**
     * @param $encoder
     * @return $this
     */
    public function setEncoder($encoder)
    {
        $this->encoder = $encoder;
        return $this;
    }

    /**
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @param $header
     * @return $this
     */
    public function setHeader($header)
    {
        $this->header = $header;
        return $this;
    }

    /**
     * @return Payload
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param $payload
     * @return $this
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @return $this|string
     */
    public function getSignature()
    {
        return $this->signature;
        return $this;
    }

    /**
     * @param string $signature
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    /**
     * Convert from token to data
     * @param $token
     * @return bool
     */
    public function load($token)
    {
        $parts = explode('.', $token);

        if (count($parts) != 3) {
            return false;
        }
        $payloadArr = json_decode(base64_decode($parts[1]), true);

        /** Load Header and Encoder Instance */
        $this->setHeader(json_decode(base64_decode($parts[0]), true));
        $this->setEncoder($this->getEncoderInstance());
        /** End */

        $this->setPayload(Payload::getInstance($payloadArr));
        $this->setSignature(base64_decode($parts[2]));

        return $this;
    }

    /**
     * @return HMac|InvalidArgumentException
     */
    public function getEncoderInstance()
    {
        $alg = $this->getHeader()['alg'];
        $signerStr = sprintf('tuanlq11\\token\\signer\\openssl\\%s', strtoupper($alg));
        if (class_exists($signerStr)) {
            return new $signerStr;
        }

        throw new InvalidArgumentException(sprintf('Algorithm "%s" is invalid!', $alg));
    }

    /**
     * @param $key
     * @return string
     */
    public function sign($key)
    {
        $this->signature = $this->encoder->sign($this->getPayload()->toJSON(false), $key);
        $this->signed = true;
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
            $this->getPayload(),
            base64_encode($this->getSignature())
        );

        return $token;
    }

    /**
     * error code: 0 - pass; 1 - invalid; 2 - remember
     * @param $secret
     * @return array
     */
    public function verify($secret, $remember_token = '')
    {
        $signVerify = $this->encoder->verify($secret, $this->getSignature(), $this->getPayload()->toJSON(false));
        $expVerify = (is_numeric($this->getPayload()->getExp()) ? $this->getPayload()->getExp() : 0) > time();
        $domainVerify = $this->getPayload()->getDomain() == \Request::root();
        $ipVerify = $this->getPayload()->getIp() == \Request::getClientIp();
        $rememberVerify = ($remember_token == $this->getPayload()->getRememberToken());

        $result = ['error' => 1, 'data' => $this->getPayload()];

        if ($signVerify && $domainVerify && $ipVerify) {
            if ($expVerify) {
                $result['error'] = 0;
            } else if (!$expVerify && $rememberVerify) {
                $result['error'] = 2;
            }
        }

        return $result;
    }

}