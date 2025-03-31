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

## install and modification
currently to install, you can just run `xcaddy --with github.com/lucienv1/powtect`  
alternatively (and if you want to modify anything), run `git clone https://github.com/lucienv1/powtect` then run [xcaddy](https://github.com/caddyserver/xcaddy) in the same directory  


to modify the html, just edit `index.html` (do not change the filename unless you also change the go embed statement in main.go) and run xcaddy  
if you modify `worker.js` just create a data: uri, and replace the current one in `index.html`  
to turn on logging, just open main.go and search and replace all instances of `//log` with `log` and uncomment the log import statement  


## credits/acknowledgments
the default spinner is from [n3r4zzurr0/svg-spinners](https://github.com/n3r4zzurr0/svg-spinners) (mit license, © Utkarsh Verma)  
the noscript warning icon is from [la-moore/scarlab-icons](https://github.com/la-moore/scarlab-icons) (mit license, © LaMoore)  
very heavily inspired by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis)  
