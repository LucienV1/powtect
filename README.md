# powtect
### A proof of work verification module for caddy
Example Caddyfile:
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
This sets the required number of leading zeros to 4, the time before expiration of cookies to half an hour, the prefix of the cookies to _powtect, the private key to the environment variable POWTECTKEY, and whitelists the useragents "example1" and "example2".  

The default settings are:  
level 4, ttl 3600 (one hour), cookie prefix "_powtect," and no whitelist.  
The key, if not provided, is randomly generated on startup, so verification will have to be redone.  

## Install and modification
Currently, to install, you can just run `xcaddy build --with github.com/lucienv1/powtect`  
Alternatively, if you want to modify anything, run `git clone https://github.com/lucienv1/powtect` then run [xcaddy](https://github.com/caddyserver/xcaddy) in the same directory  


To modify the html, just edit `index.html` (do not change the filename unless you also change the go embed statement in main.go) and run xcaddy  
If you modify `worker.js` create a data: uri, and replace the current one in `index.html`  
To turn on logging, just open main.go and search and replace all instances of `//log` with `log` and uncomment the log import statement  


## Credits/acknowledgments
The default spinner is from [n3r4zzurr0/svg-spinners](https://github.com/n3r4zzurr0/svg-spinners) (mit license, © Utkarsh Verma)  
The noscript warning icon is from [la-moore/scarlab-icons](https://github.com/la-moore/scarlab-icons) (mit license, © LaMoore)  
Very heavily inspired by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis)  
