<?php

/**
 * Standalone self-check for the KEYCLOAK_API_KEY requirement.
 * Run: php tests/api_key_check.php
 *
 * Verifies:
 *   1. Constructor throws RuntimeException when api_key is empty.
 *   2. getHttpClient() injects the X-API-KEY header when api_key is set.
 */

require __DIR__ . '/../vendor/autoload.php';

use Edoaurahman\KeycloakSso\KeycloakProviderService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;

/** Minimal config repo: get('keycloak.foo', $default). */
class FakeConfigRepo
{
    public function __construct(private array $data) {}
    public function get($key, $default = null)
    {
        // supports dotted 'keycloak.api_key'
        $segments = explode('.', $key);
        $val = $this->data;
        foreach ($segments as $s) {
            if (!is_array($val) || !array_key_exists($s, $val)) {
                return $default;
            }
            $val = $val[$s];
        }
        return $val;
    }
}

/** ArrayAccess app so Facade::resolveFacadeInstance('config') works. */
class FakeApp implements ArrayAccess
{
    public function __construct(private array $services) {}
    public function offsetExists($k): bool { return isset($this->services[$k]); }
    public function offsetGet($k): mixed { return $this->services[$k]; }
    public function offsetSet($k, $v): void { $this->services[$k] = $v; }
    public function offsetUnset($k): void { unset($this->services[$k]); }
}

function bootConfig(array $keycloak): void
{
    Facade::clearResolvedInstances();
    Facade::setFacadeApplication(new FakeApp([
        'config' => new FakeConfigRepo(['keycloak' => $keycloak]),
    ]));
}

$baseConfig = [
    'base_url' => 'https://kc.example.com/',
    'realms' => 'master',
    'api_url' => 'https://kc.example.com/',
    'client_id' => 'cid',
    'client_secret' => 'secret',
    'client_uuid' => 'uuid',
];

$failures = 0;

// 1. empty api_key -> throw
bootConfig($baseConfig + ['api_key' => null]);
try {
    new KeycloakProviderService(new Request(), 'cid', 'secret', 'https://app/callback');
    echo "FAIL: no exception thrown for empty api_key\n";
    $failures++;
} catch (\RuntimeException $e) {
    assert(str_contains($e->getMessage(), 'KEYCLOAK_API_KEY'));
    echo "PASS: throws RuntimeException when api_key empty\n";
}

// 2. api_key set -> X-API-KEY header on http client
bootConfig($baseConfig + ['api_key' => 'sekret-key-123']);
$svc = new KeycloakProviderService(new Request(), 'cid', 'secret', 'https://app/callback');

$m = new \ReflectionMethod($svc, 'getHttpClient');
$m->setAccessible(true);
$client = $m->invoke($svc);

$cfg = $client->getConfig(); // Guzzle 7 exposes merged config incl. default headers
$header = $cfg['headers']['X-API-KEY'] ?? null;

if ($header === 'sekret-key-123') {
    echo "PASS: X-API-KEY header injected into Guzzle client\n";
} else {
    echo "FAIL: X-API-KEY header missing/wrong: " . var_export($header, true) . "\n";
    $failures++;
}

echo $failures === 0 ? "\nALL CHECKS PASSED\n" : "\n$failures CHECK(S) FAILED\n";
exit($failures === 0 ? 0 : 1);
