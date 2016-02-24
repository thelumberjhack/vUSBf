FROM debian:jessie

RUN apt-get update && \
    apt-get install -qq -y --no-install-recommends \
    build-essential \
    openssh-client \
    openssl \
    ca-certificates \
    git \
    curl \
    python \
    unzip && \
    rm -rf /var/lib/apt/lists/*




git clone https://github.com/gcc-mirror/gcc.git

git clone https://github.com/SPICE/usbredir
cd usbredir

git clone https://github.com/qemu/qemu.git
cd qemu
./config --enable-usb-redir --enable-libusb


git clone git@github.com:Fuzion24/linux.git
cd linux
git checkout kcov
make defconfig
make -j8
