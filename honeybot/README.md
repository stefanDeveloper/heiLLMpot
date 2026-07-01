# Honeybot Docker Image

To build and push the Docker image to GitHub Container Registry (GHCR):

```bash
export CR_PAT="YOUR_GITHUB_PERSONAL_ACCESS_TOKEN"
echo $CR_PAT | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

docker build -t ghcr.io/YOUR_GITHUB_USERNAME/heillmpot-honeybot:latest ./honeybot

docker push ghcr.io/YOUR_GITHUB_USERNAME/heillmpot-honeybot:latest
```

**Note:** Ensure your Docker Desktop is running before executing these commands and remember that GitHub Container Registry requires your username to be all lowercase!
