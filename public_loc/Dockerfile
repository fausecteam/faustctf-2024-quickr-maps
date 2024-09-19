# syntax=docker/dockerfile:1

FROM faust.cs.fau.de:5000/backend_loc_deps
#FROM localhost/test/backend_loc_deps

COPY *.go ./ 

RUN CGO_ENABLED=0 GOOS=linux go build -o /public-loc

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/reference/dockerfile/#expose
EXPOSE 4242

CMD ["/public-loc"]
