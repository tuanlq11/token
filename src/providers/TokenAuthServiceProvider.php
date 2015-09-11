<?php
namespace tuanlq11\token\providers;
use Illuminate\Support\ServiceProvider;

/**
 * Class TokenAuthServiceProvider
 * @author tuanlq11
 * @package tuanlq11\token\providers
 */
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