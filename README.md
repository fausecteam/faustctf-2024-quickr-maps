# CI Example for a service using docker-compose

The .gitlab-ci.yml in this repo builds and pushes all possible images (docker-compose.yml is parsed and used to call kaniko).

In the vulnbox build process, the compose file is used to pull all images and include them in the vm.

# Docu

## private loc server Docker Container

```
docker build --tag private-loc .
docker run -d -p 4242:4242 private-loc:latest
```

## private loc server

-   /debug"
    Returns the all the stored locations

-   GET /location/{id}
    Adds a new location to given ID. Location is sent as an json request 

TODO: add logic so that it accepcs
body = {"lat": 24, "lon": 21, "tag": "testing"}

as well. Currently it only accepts

body = [{"lat": 24, "lon": 21, "tag": "testing"}]
body = [{"lat": 24, "lon": 21, "tag": "testing"}, ...]

Example how to use the endpoint with python:

```python
userid = uuid.uuid4().hex
url = HOSTNAME + ":" + PORT + "/location/" + userid

coord_json = {"lat": coord[0], "lon": coord[1], "tag": "testing"}

r = requests.post(url=url, json=[coord_json], timeout=2)
```

-   POST /location/{id}
    gets all locations related to a user

```
userid = uuid.uuid4().hex
url = HOSTNAME + ":" + PORT + "/location/" + userid
r = requests.get(url=url, timeout=2)
```

- POST  /share/{id}?receiver=<receiverId>

TODO: document shareing functionallity.
Currently one can only share all their own locations to someone else 

Issues: If all teams get the same flag, an adversary can corrupt the flag by adding flags to the corresponding account. Then one needs to filter this out.
Solution: Use a timestamp or tag make filtering easier
