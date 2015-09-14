<?php
return [
  'secret' => env('TOKEN.SECRET', 'BupsNIvC$YE00495anfYz32&f19km43ymJ83b!ilT6tNgk5hNzFZKV&a$vqOEkdlA5ZfrS252flphjsIyusWbO7GTX%$v6c3rePR'),
  'alg'  => env('TOKEN.ALG', 'HS256'),
  'identify' => env('TOKEN.IDENTIFY', 'email'),
  'ttl' => env('TOKEN.TTL', 300) // Second
];