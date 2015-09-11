<?php

namespace tuanlq11\token\middleware;

use tuanlq11\token\Token;
use Closure;

/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 1:07 PM
 */
class TokenMiddleware
{
  public function handle(\Request $request, Closure $next)
  {
    $token = $request->get('_token', false);
    if (!$token) {
      return \Response::json(['error' => 'Token is empty.']);
    }

    $tokenMgr = new Token();
    if (!$tokenMgr->fromToken($token)) {
      return \Response::json(['error' => 'Token is invalid or exired']);
    }

    return $next($request);
  }
}