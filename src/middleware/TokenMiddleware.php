<?php

namespace tuanlq11\token\middleware;

use tuanlq11\token\Token;
use Closure;
use Response;

/**
 * Created by PhpStorm.
 * User: tuanlq11
 * Date: 9/11/15
 * Time: 1:07 PM
 */
class TokenMiddleware
{
  public function handle($request, Closure $next)
  {
    $result = [
      'error' => \Config::get('token.error-code'),
      'message' => '',
    ];

    $token = $request->get('token', false);

    if (!$token) {
      $result['message'] = 'Token is empty';
      return Response::json($result);
    }

    $tokenMgr = new Token();
    if (!$tokenMgr->fromToken($token)) {
      $result['message'] = 'Token is invalid or exired';
      return Response::json($result);
    }

    return $next($request);
  }
}