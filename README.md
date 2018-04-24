# Develop cacheable sites by levering HTTP
This piece of example code uses the [Symfony 4](https://symfony.com/doc/4.0/index.html) framework to illustrate how you can leverage HTTP to develop cacheable sites.
 
The code uses the following HTTP concepts:
 
 * The use of `Cache-Control` headers using directives like `Public`, `Private` to decide which HTTP responses are cacheable and which are not
 * The use of `Cache-Control` headers using directives like `Max-Age` and `S-Maxage` to determine how long HTTP responses can be cached
 * Cache variations based on the `Vary` header
 * Conditional requests based on the `Etag` header
 * Returning an `HTTP 304` status code when content was successfully revalidated
 * Content negotiation and language selection based on the `Accept-Language` header
 * Block caching using [Edge Side Includes](https://www.w3.org/TR/esi-lang)
 * Client-side session storage based on [JSON Web Tokens](https://jwt.io)
 
## Cacheable
 
The output that this example code generates is highly cacheable. The proper `Cache-Control` headers are used to store the output in an HTTP cache.
 
If a reverse caching proxy (like [Varnish](https://www.varnish-cache.org/)) is installed in front of this application, it will respect the *time-to-live* that was set by the application.

Reverse caching proxies will also create cache variations by respecting the `Vary` header. A separate version of the response is stored in cache per language.

Non-cacheable content blocks will not cause a full miss on the page. These content blocks are loaded separately using *ESI*.

*ESI* tags are rendered by the reverse proxy. If the code notices that there's no *reverse caching proxy* in front of the application, it will render the output inline, without ESI.

## Conditional requests

This example code uses *conditional requests* that only loads the full page when the content has modified. 

It uses the `ETag` response header to expose the fingerprint of a page. And validates if the `If-None-Match` request header matches that fingerprint. If so, the execution of the code is stopped and an `HTTP/304 Not Modified` response is returned without any payload.

The fact that a `HTTP/304 Not Modified` response returns no payload, is an optimization in terms of bandwidth. But stopping the execution of the code, also reduces the load on the server.

The example code supports *conditional requests* via an the [CondtionalRequestListener](/src/EventListener/ConditionalRequestListener.php).

Etags are stored in Redis before the output is returned, which happens in the [onKernelResponse](/src/EventListener/ConditionalRequestListener.php#L36) method. This means you need a [Redis](https://redis.io) dependency. I'm using the [Symfony Redis bundle](https://github.com/symfony-bundles/redis-bundle) for that.

Etags are validated from Redis in the [onKernelRequest](/src/EventListener/ConditionalRequestListener.php#L27) method. If the Etag matches, the HTTP response is immediately returned, and the rest of the application bypassed.
 
```php
<?php
namespace App\EventListener;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use SymfonyBundles\RedisBundle\Redis\Client as RedisClient;

class ConditionalRequestListener
{
    protected $redis;

    public function __construct(RedisClient $redis)
    {
        $this->redis = $redis;
    }

    protected function isModified(Request $request, $etag)
    {
        if ($etags = $request->getETags()) {
             return in_array($etag, $etags) || in_array('*', $etags);
        }
        return true;
    }

    public function onKernelRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $etag = $this->redis->get('etag:'.md5($request->getUri()));
        if(!$this->isModified($request,$etag)) {
            $event->setResponse(Response::create('Not Modified',Response::HTTP_NOT_MODIFIED));
        }
    }
    
    public function onKernelResponse(FilterResponseEvent $event)
    {
        $response = $event->getResponse();
        $request = $event->getRequest();

        $etag = md5($response->getContent());
        $response->setEtag($etag);
        if($this->isModified($request,$etag)) {
            $this->redis->set('etag:'.md5($request->getUri()),$etag);
        }
    }
}
```

## Authentication

The `/private` page is protected by a layer of authentication. The Symfony frameworks provides built-in authentication support base on the [security bundle](https://symfony.com/doc/current/4.0/security.html).

### Symfony security bundle

This bundle provides a security configuration file: [config/packages/security.yml](/config/packages/security.yml). Using simple configuration, as illustrated in the example below, you can define users, roles, and routes that require authentication.

```
security:
    access_denied_url: /login
    encoders:
      Symfony\Component\Security\Core\User\User:
        algorithm: bcrypt
        cost: 12
    providers:
      in_memory:
        memory:
          users:
            admin:
              password: $2y$12$R.XN53saKaGFZ5Zqqpv5h.9NzwP0RH4VlEGmRryW1G3cM3ov1yq32
              roles: 'ROLE_ADMIN'
    firewalls:
      dev:
        pattern: ^/(_(profiler|wdt)|css|images|js)/
        security: false
      main:
        anonymous: true
        form_login:
          check_path:               /login
    access_control:
        - { path: ^/private, roles: ROLE_ADMIN }
```

This example protects the `/private` route, but unfortunately, this information is stored in *PHP session variables*, which are stored server side. Accessing this information requires access to the backend and requires a cache bypass.

### JSON Web Tokens

Luckily, there is a way to store session state at the client-side, which doesn't require backend access. We can use [JSON Web Tokens](https://jwt.io) to store this information.

The *JWT* will be stored in the *token cookie*, which will be managed by the application, **but which can also be validated by Varnish**.

The [LexikJWTAuthenticationBundle](https://github.com/lexik/LexikJWTAuthenticationBundle) can serve as an extension to the standard security bundle and requires just a little bit of extra configuration.

We'll modify [config/packages/security.yml](/config/packages/security.yml) and add custom handlers and a custom authenticator:

```
security:
    access_denied_url: /login
    encoders:
      Symfony\Component\Security\Core\User\User:
        algorithm: bcrypt
        cost: 12
    providers:
      in_memory:
        memory:
          users:
            admin:
              password: $2y$12$R.XN53saKaGFZ5Zqqpv5h.9NzwP0RH4VlEGmRryW1G3cM3ov1yq32
              roles: 'ROLE_ADMIN'
    firewalls:
      dev:
        pattern: ^/(_(profiler|wdt)|css|images|js)/
        security: false
      main:
        anonymous: true
        stateless: true
        form_login:
          check_path:               /login
          success_handler:          App\Security\JwtAuthenticationSuccessHandler
          failure_handler:          App\Security\JwtAuthenticationFailureHandler
        guard:
          authenticators:
            - lexik_jwt_authentication.jwt_token_authenticator
    access_control:
        - { path: ^/private, roles: ROLE_ADMIN }
```

The JWT bundle also has its own configuration file under [config/packages/lxik_jwt_authentication.yml](/config/packages/lxik_jwt_authentication.yml) as illustrated below:

```
lexik_jwt_authentication:
  private_key_path: '%kernel.project_dir%/%env(JWT_PRIVATE_KEY_PATH)%'
  public_key_path: '%kernel.project_dir%/%env(JWT_PRIVATE_KEY_PATH)%'
  token_ttl: 3600
  encoder:
    signature_algorithm: HS256
    service: lexik_jwt_authentication.encoder.lcobucci
  token_extractors:
    cookie:
      enabled: true
      name: token
```

This configuration file defines crypto key locations, the lifetime of the token, the algorithm to use for encryption of the signature and the service to encode and decode the token. You'll also notice that a *token cookie* is used to store the token.

> The default algorithm is *RS256* which uses a private and a public key. This example is based on *HS256* which is an *HMAC* signature that only has a private key. That's why the private and public key point to the same file.

### A website, not an API

JWT is mostly used for API authentication, and the [LexikJWTAuthenticationBundle](https://github.com/lexik/LexikJWTAuthenticationBundle) is tailored to the needs of an API. This means that the output is in JSON format. In order to make this HTML-based, I defined a custom event listener and 2 custom handlers.

The [App\Security\JwtAuthenticationSuccessHandler](/src/Security/JwtAuthenticationSuccessHandler.php) will set the *token* cookie and redirect to the `/private` page upon successful authentication, instead of displaying the token in JSON format.

The [App\Security\JwtAuthenticationFailureHandler](/src/Security/JwtAuthenticationFailureHandler.php) will redirect back to the `/login` when the authentication fails, instead of displaying a JSON error.

The [App\EventListener\JwtAuthenticationListener](/src/EventListener/JwtAuthenticationListener.php) will intercept JSON errors when the token has expired, or is invalid. It will dispatch the `/login` page when that happens.   

## Varnish

To see the impact of this code, I would advise you to install [Varnish](https://www.varnish-cache.org/). Varnish will respect the *HTTP response headers* that were set and will cache the output.

This is the minimum amount of [VCL code](https://www.varnish-cache.org/docs/trunk/reference/vcl.html#varnish-configuration-language) you need to make this work:

```
vcl 4.0;

import digest;
import std;
import cookie;
import var;

backend default {
    .host = "localhost";
    .port = "8000";
    .probe = {
         .url = "/";
         .interval = 5s;
         .timeout = 5s;
         .window = 5;
         .threshold = 3;
     }
}


sub vcl_recv {
    var.set("key","SlowWebSitesSuck");
    set req.url = std.querysort(req.url);
    if(req.http.accept-language ~ "^\s*(nl)") {
        set req.http.accept-language = regsub(req.http.accept-language,"^\s*(nl).*$","\1");
    } else {
        set req.http.accept-language = "en";
    }
    set req.http.Surrogate-Capability="key=ESI/1.0";
    if ((req.method != "GET" && req.method != "HEAD") || req.http.Authorization) {
        return (pass);
    }
    call jwt;
    if(req.url == "/private" && req.http.X-Login != "true") {
        std.log("Private content, X-Login is not true");
        return(synth(302,"/logout"));
    }
    return(hash);
}

sub vcl_backend_response {
    set beresp.http.x-host = bereq.http.host;
    set beresp.http.x-url = bereq.url;
    if(beresp.http.Surrogate-Control~"ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi=true;
    }
}

sub vcl_deliver {
    unset resp.http.x-host;
    unset resp.http.x-url;
    unset resp.http.vary;
}

sub vcl_synth {
    if (resp.status == 301 || resp.status == 302) {
        set resp.http.location = resp.reason;
        set resp.reason = "Moved";
        return (deliver);
    }
}

sub jwt {
    unset req.http.X-Login;
    std.log("Trying to find token cookie");
    if(req.http.cookie ~ "^([^;]+;[ ]*)*token=[^\.]+\.[^\.]+\.[^\.]+([ ]*;[^;]+)*$") {
        std.log("Token cookie found");
        cookie.parse(req.http.cookie);
        cookie.filter_except("token");
        var.set("token", cookie.get("token"));
        var.set("header", regsub(var.get("token"),"([^\.]+)\.[^\.]+\.[^\.]+","\1"));
        var.set("type", regsub(digest.base64url_decode(var.get("header")),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1"));
        var.set("algorithm", regsub(digest.base64url_decode(var.get("header")),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1"));

        if(var.get("type") != "JWT" || var.get("algorithm") != "HS256") {
            std.log("Invalid token header");
            return(synth(400, "Invalid token header"));
        }

        var.set("rawPayload",regsub(var.get("token"),"[^\.]+\.([^\.]+)\.[^\.]+$","\1"));
        var.set("signature",regsub(var.get("token"),"^[^\.]+\.[^\.]+\.([^\.]+)$","\1"));
        var.set("currentSignature",digest.base64url_nopad_hex(digest.hmac_sha256(var.get("key"),var.get("header") + "." + var.get("rawPayload"))));
        var.set("payload", digest.base64url_decode(var.get("rawPayload")));
        var.set("exp",regsub(var.get("payload"),{"^.*?"exp"\s*:\s*(\w+).*?$"},"\1"));
        var.set("username",regsub(var.get("payload"),{"^.*?"username"\s*:\s*"(\w+)".*?$"},"\1"));

        if(var.get("signature") != var.get("currentSignature")) {
            std.log("Invalid token signature");
            return(synth(400, "Invalid token signature"));
        }

        std.log("Ready to validate username");

        if(var.get("username") ~ "^\w+$") {
            std.log("Username: " + var.get("username"));
            if(std.time(var.get("exp"),now) >= now) {
                std.log("JWT not expired");
                set req.http.X-Login="true";
            } else {
            set req.http.X-Login="false";
                std.log("JWT expired");
            }
        }
    }
}

```

**You will need to install the [libvmod-digest](https://github.com/varnish/libvmod-digest) in order to process the *JWT*.**

**This piece of *VCL* code assumes that Varnish is installed on port 80 and your webserver on port 8000 on the same machine.**

This *vcl* file doesn't just take care of caching, but also validates the *JWT* for the `/private` route. The validation happens in the custom `sub jwt` procedure.

* It validates the *token cookie*
* In case of a mismatch, an *403 error* is returned
* The login state is extracted from the encoded JSON and stored in the custom `X-Login` request header
* The PHP code performs *cache variations* on the `X-Login` request header to have 2 versions of the pages that depend on the login state 

**If you're planning to change the secret key in your [.env.dist](/.env.dist) file, please also change it in your [VCL file](/vcl/default.vcl#L22).**

## Summary

The application handles nearly all of the caching logic. The only tricky bit is the authentication and the cache variations for the private part of the site.

Luckily, we can validate the *JSON Web Tokens* in *VCL* by performing some *regex magic* and by using some digest functions, provided by `vmod_digest`.

The backend is only accessed under the following circumstances:

* The first hit
* Cache variations
* The *POST* call on the login form

All the rest is delivered from cache. This strategy makes the site extremely cacheable.