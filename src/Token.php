<?php

namespace tuanlq11\token;

use App\User;
use Carbon\Carbon;
use Illuminate\Contracts\Encryption\DecryptException;
use tuanlq11\token\signer\Signer;
use Cache;
use Config;
use Crypt;

/**
 * Class Token
 * @author tuanlq11
 * @package tuanlq11\token
 */
class Token
{
    /** @var Signer */
    protected $signer;

    /** @var  JWT */
    protected $jwt;

    /** @var  String */
    protected $alg;

    /** @var  String */
    protected $identify;

    /** @var  String */
    protected $secret;

    /** @var  Integer */
    protected $ttl;

    /** @var  bool */
    protected $encrypt;

    /** Static prefix cache key */
    const PREFIX_CACHE_KEY = 'tuanlq11.token.blacklist.';

    /** @var  Token */
    private static $instance;

    /**
     * @return Signer
     */
    public function getSigner()
    {
        return $this->signer;
    }

    /**
     * @param Signer $signer
     */
    public function setSigner($signer)
    {
        $this->signer = $signer;
    }

    /**
     * @return JWT
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * @param JWT $jwt
     */
    public function setJwt($jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * @return String
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param String $alg
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
    }

    /**
     * @return String
     */
    public function getIdentify()
    {
        return $this->identify;
    }

    /**
     * @param String $identify
     */
    public function setIdentify($identify)
    {
        $this->identify = $identify;
    }

    /**
     * @return String
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @param String $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * @return int
     */
    public function getTtl()
    {
        return $this->ttl;
    }

    /**
     * @param int $ttl
     */
    public function setTtl($ttl)
    {
        $this->ttl = $ttl;
    }

    /**
     * @return boolean
     */
    public function isEncrypt()
    {
        return $this->encrypt;
    }

    /**
     * @param boolean $encrypt
     */
    public function setEncrypt($encrypt)
    {
        $this->encrypt = $encrypt;
    }

    function __construct()
    {
        $this->setAlg(Config::get('token.alg'));
        $this->setIdentify(Config::get('token.identify'));
        $this->setSecret(Config::get('token.secret'));
        $this->setTtl(Config::get('token.ttl'));
        $this->setEncrypt(Config::get('token.encrypt'));

        return $this;
    }

    /**
     * Generate instance for static
     * @return Token
     */
    public static function getInstance()
    {
        if (self::$instance == null) {
            self::$instance = new Token();
        }

        return self::$instance;
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

        $user = User::whereEmail($credentials[$this->getIdentify()])->first();
        $uid = $user->{$this->getIdentify()};

        $payload = new Payload($uid, time() + $this->getTtl());
        $payload->generateSalt($this->getSecret());

        return $this->toToken($payload);
    }

    /**
     * @param $token
     * @return bool|User
     */
    public function fromToken($token = null)
    {
        $token = $token ? $token : \Input::get('token');

        try {
            $token = $this->isEncrypt()?Crypt::decrypt($token):$token;
        } catch (DecryptException $e) {
            return false;
        }

        $key = self::PREFIX_CACHE_KEY . $token;

        if (Cache::has($key)) {
            return false;
        }

        if (!($signer = Signer::getInstance($token))) {
            return false;
        }

        if (($payload = $signer->verify($this->getSecret()))) {
            return User::where($this->getIdentify(), '=', $payload->getUid())->first();
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
            $uid = $user->{$this->getIdentify()};
            $payload = new Payload($uid, time() + $this->getTtl());
            $newToken = $this->toToken($payload);

            // Blacklist
            $key = self::PREFIX_CACHE_KEY . $token;
            Cache::put($key, [], Carbon::now()->addSecond($this->getTtl()));
            // End

            return $newToken;
        }

        return false;
    }

    /**
     * @param $payload Payload
     * @return string
     */
    protected function toToken($payload)
    {
        $signer = new Signer();
        $signer->setHeader(['alg' => $this->getAlg()]);
        $signer->setEncoder($signer->getEncoderInstance());
        $signer->setPayload($payload);
        $signer->sign($this->getSecret());

        $token = $signer->getTokenString();
        $token = $this->isEncrypt()?Crypt::encrypt($token):$token;

        return $token;
    }

}