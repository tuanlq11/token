<?php

namespace tuanlq11\token;

use tuanlq11\token\signer\Signer;

/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/14/15
 * Time: 8:23 AM
 */
class Payload
{

    /** @var  int seconds */
    protected $exp;

    /** @var  string */
    protected $uid;

    /** @var  string */
    protected $ip;

    /** @var  string */
    protected $salt;

    /** @var  string */
    protected $domain;

    /**
     * Payload constructor.
     * @param int $exp
     * @param string $uid
     * @param string $ip
     * @param string $salt
     * @param string $domain
     */
    public function __construct($uid = null, $exp = null, $ip = null, $domain = null, $salt = null)
    {
        $this->exp = $exp;
        $this->uid = $uid;
        $this->ip = $ip;
        $this->salt = $salt;
        $this->domain = $domain;

        return $this;
    }

    /**
     * Get instance from array
     * @param $array
     * @return $this
     */
    public static function getInstance($array)
    {
        return (new Payload())->fromArray($array);
    }

    /**
     * @return int
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * @param $exp
     * @return $this
     */
    public function setExp($exp)
    {
        $this->exp = $exp;
        return $this;
    }

    /**
     * @return string
     */
    public function getUid()
    {
        return $this->uid;
    }

    /**
     * @param $uid
     * @return $this
     */
    public function setUid($uid)
    {
        $this->uid = $uid;
        return $this;
    }

    /**
     * @return string
     */
    public function getIp()
    {
        return $this->ip;
    }

    /**
     * @param $ip
     * @return $this
     */
    public function setIp($ip)
    {
        $this->ip = $ip;
        return $this;
    }

    /**
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @param $salt
     * @return $this
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;
        return $this;
    }

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @param $domain
     * @return $this
     */
    public function setDomain($domain)
    {
        $this->domain = $domain;
        return $this;
    }

    /**
     * Generate new salt
     * @param string $secret
     * @return $this
     */
    public function generateSalt($secret = '')
    {
        $data = [
            'rnd0' => str_random(rand(16, 64)),
            'time' => time(),
            'secret' => $secret,
            'rnd1' => str_random(rand(16, 64))
        ];
        shuffle($data);
        $middleCode = base64_encode(json_encode($data));
        shuffle($data);
        $key = base64_encode(json_encode($data));

        $this->salt = md5($this->getUid()) . hash_hmac('sha256', $middleCode, $key);
        return $this;
    }

    /**
     * Import data from array
     * @param $data
     * @return $this
     */
    public function fromArray($data)
    {
        if (!is_array($data))
            return $this;

        return $this->setDomain(isset($data['domain']) ? $data['domain'] : null)
            ->setIp(isset($data['ip']) ? $data['ip'] : null)
            ->setExp(isset($data['exp']) ? $data['exp'] : null)
            ->setSalt(isset($data['salt']) ? $data['salt'] : null)
            ->setUid(isset($data['uid']) ? $data['uid'] : null);
    }

    /**
     * Convert to array
     * @return array
     */
    public function toArray($shuffle = true)
    {
        $this->setIp($this->getIp() ? $this->getIp() : \Request::getClientIp());
        $this->setDomain($this->getDomain() ? $this->getDomain() : \Request::root());

        $data = [
            'uid' => $this->getUid(),
            'exp' => $this->getExp(),
            'ip' => $this->getIp(),
            'domain' => $this->getDomain(),
            'salt' => $this->getSalt()
        ];

        if ($shuffle) {
            $data = $this->shuffle_assoc($data);
        }

        return $data;
    }

    /**
     * @param $array
     * @return array
     */
    private function shuffle_assoc($array)
    {
        $result = [];
        $array_keys = array_keys($array);
        shuffle($array_keys);

        foreach ($array_keys as $key) {
            $result[$key] = $array[$key];
        }

        return $result;
    }

    /**
     * Convert to json
     * @return string
     */
    public function toJSON($shuffle = true)
    {
        return json_encode($this->toArray($shuffle));
    }

    /**
     * @return string
     */
    public function __toString()
    {
        $data = $this->toArray(false);
        return base64_encode(json_encode($data));
    }
}