# my-keycloak
**1. Target**
- Custom keycloak image with custom cache to store user's session to avoid user's session lost when keycloak restart.

**2. How to run**
- Run `docker-compose up -d` to start keycloak and postgres.
- Access to `http://localhost:8090` to access keycloak admin console (user `admin`/ password `admin`).
- Create a new realm, client, user and login with user account by api.
```angular2html
curl --location --request POST 
'http://localhost:8090/realms/[REAL_NAME]/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=[USERNAME]' \
--data-urlencode 'password=[PASSWORD]' \
--data-urlencode 'client_secret=[CLIENT_SECRET]' \
--data-urlencode 'client_id=[CLIENT_ID]'
```
- Check access token status by api.
```angular2html
curl --location --request POST 
'http://localhost:8090/realms/[REAL_NAME]/protocol/openid-connect/token/introspect' \
--header 'Authorization: Basic [CLIENT_BASIC_AUTH_TOKEN]' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'token=[ACCESS_TOKEN]'
```
- To restart keycloak, run `docker restart keycloak` and access to `http://localhost:8090` again, you will see that your session is still alive.
- Recheck access token status by api.

**3. Reference**
- https://keycloak.discourse.group/t/preserve-user-sessions-over-keycloak-restart/19367/7
- https://keycloak.discourse.group/t/jgroups-infinispan-bedevilling-no-db-table-created-unable-to-persist-infinispan-internal-caches-as-no-global-state-enabled/16229/13
- https://www.keycloak.org/server/all-config
