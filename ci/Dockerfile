FROM fedora:31

RUN dnf install -y python3-pip python3-gobject gtk3 python3-pytest python3-coverage python3-devel gcc

ADD requirements.txt /

RUN pip3 install -r requirements.txt
