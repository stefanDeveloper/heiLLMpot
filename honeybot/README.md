# Honeybot Docker Image

To build and push the Docker image to Docker Hub (or your preferred container registry):

```bash
docker login -u YOUR_DOCKERHUB_USERNAME

docker build -t YOUR_DOCKERHUB_USERNAME/honeybot:latest ./honeybot

docker push YOUR_DOCKERHUB_USERNAME/honeybot:latest
```

**Note:** Ensure your Docker service is running before executing build commands.
