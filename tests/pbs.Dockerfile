FROM debian:trixie-slim

RUN apt-get update && apt-get -y install curl wget apt-transport-https && \
    echo "deb http://download.proxmox.com/debian/pbs-client trixie main" > /etc/apt/sources.list.d/pbs-client.list && \
    wget https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-trixie.gpg && \
    apt-get update && apt-get install -y proxmox-backup-client

RUN groupadd --gid 1000 gopbs && useradd --system --uid 1000 --gid 1000 gopbs
USER gopbs

ENTRYPOINT [ "/usr/bin/pxar" ]