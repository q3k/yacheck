checkinator
===

Yet another presence-over-DHCP tool. Clone of the Warsaw Hackerspace's [checkinator](https://code.hackerspace.pl/hswaw/hscloud/src/branch/master/hswaw/checkinator). Implemented for [FAFO](https://fa-fo.de).

Design criteria
---

1. Basic functionality: OAuth2 login, list present devices, manage own devices, claim device
2. Simple to deploy: pure Go, local DB (BoltDB)
3. Easy to migrate over to different lease providers (currently supports the Kea DHCPv4 server)
4. Data sourced purely from leases: not consulting local ARP cache or performing any subnet checks ; if a device is in the leasefile then it can be claimed

Authentication/Authorization
---

By default all users must be authenticated to see who's at the space. TODO(q3k): add flag to allow public read-only access.

There's also an API user mechanism. `-api_user foo:bar` will allow HTTP basic auth with username foo and password bar to `/api.json` which offers a post-auth, read-only view of the system.

Running locally
---

Set up an application on an OIDC IDP (we use Forgejo), then:

```
$ cat << EOF >test.leases
address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
127.0.0.1,00:11:22:33:44:55,00:11:22:33:44:55,3600,1727130647,1,0,0,localtest,0,,0
EOF
$ go run . \
    -oauth_auth_url XXX \
    -oauth_token_url XXX \
    -oauth_user_info_url XXX \
    -oauth_client_id XXX \
    -oauth_client_secret XXX \
    -public_address http://127.0.0.1:8080 \
    -lease_file test.leases
```

Visit localhost:8080 and you should be able to claim the device at 127.0.0.1.

Production deployment
---

```
$ go build ./
$ scp yacheck prod@prod:/usr/local/bin/yacheck
```

And run with appropriate flags (see `-help` for more info).
