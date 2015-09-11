<?php
/**
 * Created by PhpStorm.
 * User: archlinux
 * Date: 9/11/15
 * Time: 7:56 AM
 */

namespace tuanlq11\token;

use Illuminate\Support\ServiceProvider;

class TokenAuthServiceProvider extends ServiceProvider {

  /**
   * Register the service provider.
   *
   * @return void
   */
  public function register()
  {
    $this->mergeConfigFrom(__DIR__ . '/../config/config.php', 'token');
  }

}