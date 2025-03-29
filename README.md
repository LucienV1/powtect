# powtect
### a proof of work verification module for caddy
example caddyfile:
```
localhost {
    file_server
    root /path/to/root
    powtect {
        level 4
        ttl 1800
        cookieprefix "_powtect"
        key {$POWTECTKEY}
        whitelist {
            "example1"
            "example2"
        }
    }
}
```
this sets the required number of leading zeros to 4, the time before expiration of cookies to half an hour, the prefix of the cookies to _powtect, the private key to the environment variable POWTECTKEY, and whitelists the useragents "example1" and "example2".


whitelisting should not be used by itself, and should be paired with validating the ip ranges, as well as rate limiting.


the default settings are:
level 4
ttl 3600 (one hour)
cookie prefix "_powtect" (there is only one cookie, {prefix}_main)
and no whitelist.
the key, if not provided, is randomly generated on startup, so verification will have to be redone.
keys are padded or truncated to 32 bytes.


## credits
the default spinner is from [n3r4zzurr0/svg-spinners](https://github.com/n3r4zzurr0/svg-spinners)
very heavily inspired by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis)