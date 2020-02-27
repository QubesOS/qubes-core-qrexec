FROM fedora:31

RUN dnf install -y python3-pip python3-gobject gtk3 python3-pytest \
    python3-coverage python3-devel pam-devel systemd-devel pandoc gcc git make findutils

RUN git clone https://github.com/QubesOS/qubes-core-vchan-socket ~/qubes-core-vchan-socket
RUN make -C ~/qubes-core-vchan-socket all
RUN make -C ~/qubes-core-vchan-socket install LIBDIR=/usr/lib64

ADD requirements.txt /
RUN pip3 install -r requirements.txt

RUN useradd --create-home --shell /bin/bash travis --uid 2000
USER travis
