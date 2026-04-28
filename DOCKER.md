# SEAL-C in docker

SEAL-C has a Dockerfile and you are able to build the project in a container and use it directly from Docker.

## Building

Once you clone the repository, with Docker or similar (e.g. Podman) you shoudl be able to build the Docker container with:

`docker build -t sealtool .`

## Using the container

You can replace wherever you would use the `sealtool` command with the following in Linux/macOS:

- Using your locally-built image: `docker run --rm -v ${PWD}:/root sealtool:latest`
- Using the image from the GitHub Container Registry: `docker run --rm -v ${PWD}:/root ghcr.io/hackerfactor/seal-c:latest` 

In this command:

1. Docker is running the container
2. `--rm` means to delete the container after use
3. `-v ${PWD}:/root` says to map the current directory to `/root` inside the container. That way if you have files to SEAL or configuration files in your current directory they are accessible inside the container.
 
### Example

Starting from scratch, you can perform the following (this follows the steps under "Local Signing" in BUILD.md):

1. Make a new directory. In that directory place a file to sign (e.g. banana.jpg).
2. Run: `docker run --rm -v ${PWD}:/root ghcr.io/hackerfactor/seal-c:latest -g -K rsa -k seal-rsa.key -D seal-rsa.dns`
3. Once the container exits, you'll see the two files (`seal-rsa.key` and `seal-rsa.dns`) in your current directory.
4. Add the contents of the `seal-rsa.dns` to a `TXT` record under your domain.
5. Now sign your image file: `docker run --rm -v ${PWD}:/root ghcr.io/hackerfactor/seal-c:latest -s -d example.com -K rsa -k seal-rsa.key banana.jpg`
6. You should now see your signed file in the directory
7. Verify your signed file with `docker run --rm -v ${PWD}:/root ghcr.io/hackerfactor/seal-c:latest banana-seal.jpg`

