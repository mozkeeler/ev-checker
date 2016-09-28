FROM docker.io/fedora:latest
RUN dnf install -y git clang make nodejs nss-devel nspr-devel libcurl-devel npm gnutls-utils
RUN git clone https://github.com/mozkeeler/ev-checker
WORKDIR ev-checker
RUN make
RUN npm install formidable
EXPOSE 8000
CMD node server
