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

## Authentication

We use a single cookie that contains our *JSON Web Token*. The *JWT* is generated and validated by PHP. We don't use native PHP sessions. 
 
The `/private` route is only accessible if the user is logged in. The login state is stored as a JWT in the *token cookie*.  

PHP validates this token, but there's even a piece of Javascript code that reads the username from the JWT and prints it in the header.

The fact that we used client-side session storage allows for reverse caching proxies, such as Varnish, to do the validation without having to connect with the backend.

To login, please use the *admin* username and change the password hash [in the JWT section of the .env.dist file](/.env.dist). The hash is created via the PHP [password_hash](https://php.net/password_hash) function using the default Bcrypt algorithm. Please also set a *secret key* for the JWT HMAC signing.
```
###> JWT authentication ###
JWT_KEY=SlowWebSitesSuck
JWT_USERNAME=admin
JWT_PASSWORD=$2y$10$431rvq1qS9ewNFP0Gti/o.kBbuMK4zs8IDTLlxm5uzV7cbv8wKt0K
###< JWT authentication ###
```

## Varnish

To see the impact of this code, I would advise you to install [Varnish](https://www.varnish-cache.org/). Varnish will respect the *HTTP response headers* that were set and will cache the output.

This is the minimum amount of [VCL code](https://www.varnish-cache.org/docs/4.1/reference/vcl.html#varnish-configuration-language) you need to make this work:

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
    if(req.http.cookie ~ "^([^;]+;[ ]*)*token=[^\.]+\.[^\.]+\.[^\.]+([ ]*;[^;]+)*$") {
        std.log("Token cookie found");
        cookie.parse(req.http.cookie);
        cookie.filter_except("token");
        var.set("token", cookie.get("token"));
        var.set("header", regsub(var.get("token"),"([^\.]+)\.[^\.]+\.[^\.]+","\1"));
        var.set("type", regsub(digest.base64url_decode(var.get("header")),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1"));
        var.set("algorithm", regsub(digest.base64url_decode(var.get("header")),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1"));

        if(var.get("type") != "JWT" || var.get("algorithm") != "HS256") {
            return(synth(400, "Invalid token"));
        }

        var.set("rawPayload",regsub(var.get("token"),"[^\.]+\.([^\.]+)\.[^\.]+$","\1"));
        var.set("signature",regsub(var.get("token"),"^[^\.]+\.[^\.]+\.([^\.]+)$","\1"));
        var.set("currentSignature",digest.base64url_nopad_hex(digest.hmac_sha256(var.get("key"),var.get("header") + "." + var.get("rawPayload"))));
        var.set("payload", digest.base64url_decode(var.get("rawPayload")));
        var.set("exp",regsub(var.get("payload"),{"^.*?"exp"\s*:\s*(\w+).*?$"},"\1"));
        var.set("username",regsub(var.get("payload"),{"^.*?"sub"\s*:\s*"(\w+)".*?$"},"\1"));

        if(var.get("signature") != var.get("currentSignature")) {
            return(synth(400, "Invalid token"));
        }

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