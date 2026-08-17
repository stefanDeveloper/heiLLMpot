# Honeybot Docker Image

To build and push the Docker image to Docker Hub (or your preferred registry):

```bash
docker login -u YOUR_DOCKERHUB_USERNAME

docker build -t dockerphil1234/honeybot:latest ./honeybot

docker push dockerphil1234/honeybot:latest
```

**Note:** The default Terraform deployment uses `dockerphil1234/honeybot:latest` out of the box. This public pre-built image is provided as the default to simplify deployment, because the original GHCR image requires a GitHub token for access. Ensure your Docker Desktop is running before executing these commands!
