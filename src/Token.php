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
    /** @var String */
    protected $remember_token;

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

    /** @var  Integer */
    protected $blacklist_ttl;

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

    /**
     * @return String
     */
    public function getRememberToken()
    {
        return $this->remember_token;
    }

    /**
     * @param $remember_token
     * @return $this
     */
    public function setRememberToken($remember_token)
    {
        $this->remember_token = $remember_token;
        return $this;
    }

    /**
     * @return int
     */
    public function getBlacklistTtl()
    {
        return $this->blacklist_ttl;
    }

    /**
     * @param int $blacklist_ttl
     */
    public function setBlacklistTtl($blacklist_ttl)
    {
        $this->blacklist_ttl = $blacklist_ttl;
    }

    /**
     * Generate remember token
     * @param string $uid
     * @return string
     */
    public function generateRememberToken($uid = '')
    {
        $this->setRememberToken(md5(time() . $uid . str_random()));
        return $this->getRememberToken();
    }

    function __construct()
    {
        $this->setAlg(Config::get('token.alg'));
        $this->setIdentify(Config::get('token.identify'));
        $this->setSecret(Config::get('token.secret'));
        $this->setTtl(Config::get('token.ttl'));
        $this->setBlacklistTtl(Config::get('token.ttl_blacklist'));
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

        /** Remember Token */
        $remember_token = $this->generateRememberToken($uid);
        /** End */

        $payload = new Payload($uid, time() + $this->getTtl(), null, null, null, $remember_token);
        $payload->generateSalt($this->getSecret());

        return $this->toToken($payload);
    }

    /**
     * Response User from token
     * @param $token
     * @return bool|User
     */
    public function fromToken($token = null)
    {
        $token = $token ? $token : \Input::get('token');

        try {
            $token = $this->isEncrypt() ? Crypt::decrypt($token) : $token;
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

        $result = $signer->verify($this->getSecret());
        /** @var Payload $payload */
        $payload = $result['data'];
        if ($result['error'] == 0) {
            return User::where($this->getIdentify(), '=', $payload->getUid())->first();
        }

        return false;
    }

    /**
     * Response User && Remember Token from token
     * error code: 0 - pass; 1 - invalid; 2 - remember
     * @param $token
     * @return bool|User
     */
    public function fromTokenFull($token = null)
    {
        $key = self::PREFIX_CACHE_KEY . $token;
        $result = ['error' => 1, 'data' => null];

        $token = $token ? $token : \Input::get('token');
        $remember_token = \Input::get('remember_token', false);

        try {
            $token = $this->isEncrypt() ? Crypt::decrypt($token) : $token;
        } catch (DecryptException $e) {
            return false;
        }

        if (Cache::has($key)) {
            return false;
        }

        if (!($signer = Signer::getInstance($token))) {
            return false;
        }

        $payloadResult = $signer->verify($this->getSecret(), $remember_token);
        /** @var Payload $payload */
        $payload = $payloadResult['data'];
        if ($payloadResult['error'] == 0) {
            $result['error'] = 0;
            $result['data'] = User::where($this->getIdentify(), '=', $payload->getUid())->first();
            return $result;
        }

        /** Use remember token */
        if ($payloadResult['error'] == 2) {
            $result['error'] = 2;
            $result['data'] = User::where($this->getIdentify(), '=', $payload->getUid())->first();
            return $result;
        }
        /** End */

        return $result;
    }

    /**
     * @param $token
     * @return bool
     */
    public function refresh($token)
    {
        $valid = $this->fromTokenFull($token);

        if ($valid['error'] != 1) {
            $user = $valid['data'];
            $uid = $user->{$this->getIdentify()};

            /** Remember Token */
            $remember_token = $this->generateRememberToken($uid);
            /** End */

            $payload = new Payload($uid, time() + $this->getTtl(), null, null, null, $remember_token);
            $newToken = $this->toToken($payload);

            // Blacklist
            $key = self::PREFIX_CACHE_KEY . $token;
            Cache::put($key, [], Carbon::now()->addSecond($this->getBlacklistTtl()));
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
        $token = $this->isEncrypt() ? Crypt::encrypt($token) : $token;

        return $token;
    }

}