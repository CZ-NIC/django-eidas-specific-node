# Run in Docker

To build and run testing instance in docker swarm, do:

1. Edit docker/specific_proxy_service_cfg.py and change if you need something (like `PROXY_SERVICE_*` settings)
2. Edit docker/specific_connector_cfg.py and change if you need something (like `CONNECTOR_*` settings)
3. Create docker swarm cluster if you don't have it already:

docker swarm init --advertise-addr $YOUR_IP  # replace $YOUR_IP with your IP address

3. run these commands in the project root:

```sh
docker/build.sh
docker stack deploy -c docker/docker-compose.yml sps
```

And now your specific_proxy_service is running at port 8000 and your specific_connector is running at port 8001.

Demo Service Provider is available at http://localhost:8001/DemoServiceProviderRequest
