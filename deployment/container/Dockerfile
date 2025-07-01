FROM registry.access.redhat.com/ubi10:10.0

ENV USER=openadp

RUN curl -O -L https://github.com/cloudflare/cloudflared/releases/download/2025.5.0/cloudflared-linux-x86_64.rpm

RUN dnf -y update &&\
    dnf install -y python3 sqlite python3-cryptography cloudflared-linux-x86_64.rpm

ENV INSTALL_DIR="/opt/openadp"

RUN useradd ${USER} &&\
    mkdir -p ${INSTALL_DIR} &&\
    chown ${USER} ${INSTALL_DIR}


COPY proto src tools run_server.py deployment/systemd/openadp-server.conf ${INSTALL_DIR}/

USER ${USER}
WORKDIR ${INSTALL_DIR}

ENTRYPOINT [ "/usr/bin/python3", "/opt/openadp/run_server.py" ]