# gokdogan — static PE malware triage engine
# Build:  docker build -t gokdogan .
# Run:    docker run --rm -v "$PWD/samples:/samples:ro" gokdogan /samples/suspect.exe
#
# Note: Authenticode verification (WinVerifyTrust) is Windows-only and is
# skipped in this Linux image; every other analyzer runs. The container
# never executes samples and needs no network.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="gokdogan" \
      org.opencontainers.image.description="Static PE malware triage engine" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY . /app

# yara-python provides the optional YARA stage; ppdeep/pefile are core.
RUN pip install --no-cache-dir -e ".[yara]"

# Run as an unprivileged user — this tool only ever reads samples.
RUN useradd -m analyst
USER analyst

ENTRYPOINT ["gokdogan"]
CMD ["--help"]
