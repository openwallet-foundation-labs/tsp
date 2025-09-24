# Hosting

Currently, there are free, publicly reachable demo services deployed that you may use for development and testing.
Please be aware that they do not provide any guarantees on uptime or data persistence.
The domains for the various servers are as follows:

- Demo server with web GUI: [https://demo.teaspoon.world](https://demo.teaspoon.world)
- DID:WEB server to create and resolve DIDs: [https://did.teaspoon.world](https://did.teaspoon.world)
- Intermediary P: [https://p.teaspoon.world](https://p.teaspoon.world)
- Intermediary Q: [https://q.teaspoon.world](https://q.teaspoon.world)

# Self-hosting

If you prefer to host your own instances, we provide all the resources to run a local deployment in docker compose or a
cloud-based deployment with Google Cloud Run.

## Docker compose
The easiest way to run the different components on the local machine is to execute start the docker compose file in the 
root of the repository.
The docker compose deployment uses the local certificate included in the code base to enable HTTPS connections.
Therefore, you must enable the `use_local_certificate` feature flag when compiling the TSP CLI.
Otherwise, you will receive an "Unknown Certificate" error.

```bash
# the `-d` option starts the containers in the background.
docker compose up -d 
```

## Google Cloud Run
To deploy the demo applications in your own Google Cloud environment, you can either build your own Docker images 
or rely on pulling them [from GitHub](https://github.com/orgs/openwallet-foundation-labs/packages?repo_name=tsp).
To build the images yourself, use the `--target` flag to specify which image to build.

```bash
docker build --target did-server . -t your-custom-tag/did-server:version
docker build --target server . -t your-custom-tag/server:version
docker build --target intermediary . -t your-custom-tag/intermediary:version
```

Further, you need a Google Cloud Run instance and at least the "Cloud Run Developer", "Artifact Registry Reader", and
"Cloud Run Developer" access rights.
The repository contains [Knative configuration templates](https://github.com/openwallet-foundation-labs/tsp/tree/main/deploy)
that can be deployed directly to Google Cloud Run.

```bash
gcloud run services replace <filled_in_template> --project <your_project>
```