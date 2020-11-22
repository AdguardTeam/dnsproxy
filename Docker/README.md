## dnsproxy - Docker

This part of the project is to run dnsproxy in docker as server or client. The docker image pulls the current dnsproxy code, builds it and creates an alpine based docker image

Default version of docker-compose runs dnsproxy as quic server with upstream 1.1.1..1 
 1. Current version of dnsproxy docker supports `DNS-over-TLS, `DNS-over-HTTPS`, `DNSCrypt`, and `DNS-over-QUIC`
 2. Moreover, it can work as a `DNS-over-HTTPS`, `DNS-over-TLS` or `DNS-over-QUIC` server, or a simple passthrough server in a defined port

Functionalities supported by the docker image will be sub-set of the functionalities supported by dnsproxy current code

```
# docker-compose up -d
```

### Following changes required in docker-compose.yml. to start dnsproxy as `DNS-over-HTTPS`
```
SRVPORT: "443"
MODE: "server"
PROTO: "https"
```

### Following changes required in docker-compose.yml. to start dnsproxy as `DNS-over-QUIC`
```
SRVPORT: "784"
MODE: "server"
PROTO: "quic"
```


### Following changes required in docker-compose.yml. to start dnsproxy as `DNS-over-TLS`
```
SRVPORT: "853"
MODE: "server"
PROTO: "tls"
```
### Following changes required in docker-compose.yml. to start dnsproxy as `client`
```
MODE: "client"
LOCALPORT: "1234" # Any local port number
```

Remove EDNS flag in docker-compose.yml, if EDNS support is not required
