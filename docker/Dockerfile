FROM ubuntu:16.04
MAINTAINER kisec (https://github.com/kisec/VolUtility)

# Version Vars
ENV YARA_VERSION        4.0.2
ENV VOLATILITY_VERSION  2.6.1
ENV VOLUTILITY_VERSION  1.2.2

# Switch to user root
USER root

# Install OS Dependancies
RUN apt-get update && apt-get install -yq \
 autoconf \
 automake \
 autopoint \
 curl \
 gettext \
 git \
 libimage-exiftool-perl \
 libtool \
 nano \
 pkg-config \
 python-dev \
 python-pip \
 bsdmainutils \
 sudo


# Install Mongo
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E52529D4 && \
echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/4.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.0.list && \
apt-get update && \
ln -s /bin/true /usr/local/bin/systemctl && \
apt-get install -yq mongodb-org && \
rm /usr/local/bin/systemctl

# Install packages from source
# Make Tmp Dir
RUN mkdir ~/tmp_build

# Install Yara
RUN cd ~/tmp_build && \
 curl -sSL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz | \
 tar -xzC . && \
 cd yara-$YARA_VERSION && \
 bash build.sh && \
 make install && \
 curl -sSL https://github.com/VirusTotal/yara-python/archive/v$YARA_VERSION.tar.gz | \
 tar -xzC . && \
 cd yara-python-$YARA_VERSION && \
 python setup.py build && \
 python setup.py install && \
 cd ../.. && \
 rm -rf yara-$YARA_VERSION && \
 ldconfig

# Install SSDEEP
RUN cd ~/tmp_build &&\
 curl -sSL https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz | \
 tar -xzC .  && \
 cd ssdeep-2.14.1 && \
 ./configure && \
 make install && \
 cd .. && \
 rm -rf ssdeep-2.14.1 && \
 ldconfig

# Install pydeep
RUN pip install pydeep

# Install floss
RUN pip install https://github.com/williballenthin/vivisect/zipball/master && pip install https://github.com/fireeye/flare-floss/zipball/master && curl "https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss" --output /usr/bin/floss

#Install Capstone
RUN pip install capstone

#install pdbparse
RUN pip install pdbparse==1.2

# Get the maxmind database for ip lookup
RUN cd ~/tmp_build && \
 curl -sSL https://github.com/kisec/VolUtility/raw/master/extra/docker/GeoLite2-City.mmdb > GeoLite2-City.mmdb && \
 mkdir /usr/share/GeoIP/ && \
 mv GeoLite2-City.mmdb /usr/share/GeoIP/

# Install and Build libpff
RUN cd ~/tmp_build && \
 git clone https://github.com/libyal/libpff.git &&\
 cd libpff/ && \
 ./synclibs.sh && \
 ./autogen.sh && \
 ./configure --enable-python && \
 make && \
 make install && \
 ldconfig

# Install Volatility
ADD patch /opt/patch
RUN cd ~/tmp_build &&\
 git clone https://github.com/volatilityfoundation/volatility.git && \
 cd volatility && \
 patch -p1 < /opt/patch/483.patch && \
 patch -p1 < /opt/patch/553.patch && \
 patch -p1 < /opt/patch/641.patch && \
 patch -p1 < /opt/patch/642.patch && \
 patch -p1 < /opt/patch/689.patch && \
 patch -p1 < /opt/patch/694.patch && \
#git checkout tags/$VOLATILITY_VERSION && \
#Add patch
 python setup.py install

#install plugin
RUN mkdir /opt/plugins
RUN mkdir /opt/plugins_ok
RUN pip install distorm3==3.4.4 construct==2.5.5-reupload pefile pycrypto PySocks==1.7.1 unicorn==1.0.2
RUN mkdir /opt/plugins/cobalt && \
       curl --output /opt/plugins_ok/cobaltstrikescan.py  https://raw.githubusercontent.com/JPCERTCC/aa-tools/master/cobaltstrikescan.py
RUN cd /tmp && git clone https://github.com/JPCERTCC/MalConfScan.git && pip install -r MalConfScan/requirements.txt && \
  cp -R MalConfScan/malconfscan.py MalConfScan/utils/ MalConfScan/yara/ /opt/plugins_ok
 RUN  cd /opt/plugins \
  && git clone https://github.com/volatilityfoundation/community.git \
  && cd community \
  && rm -rf /opt/plugins/community/AlexanderTarasenko \
  && rm -rf /opt/plugins/community/MarcinUlikowski \
RUN cd /opt/plugins/community/YingLi \
  && touch __init__.py \
  && cd /opt/plugins/community/StanislasLejay/linux \
  && touch __init__.py \
  && cd /opt/plugins/community/DatQuoc \
  && touch __init__.py \
  && cd /opt/plugins/community/DimaPshoul \
  && sed -i 's/import volatility.plugins.malware.callstacks as/import/' malthfind.py
RUN git clone https://github.com/mnemonic-no/dnscache /opt/plugins/dnscache/

#yara rules
RUN mkdir /opt/yara
RUN git clone https://github.com/Neo23x0/signature-base /opt/yara/signature-base/

# Create Volutility User
RUN groupadd -r volutility -g 1000 && \
 useradd -r -u 1000 -g volutility -d /home/volutility -s /sbin/nologin -c "Volutility User" volutility && \
 usermod -a -G sudo volutility  && \
 mkdir /home/volutility && \
 chown -R volutility:volutility /home/volutility

# Get VolUtility
RUN cd /opt && mkdir VolUtility && chown -R volutility:volutility /opt/VolUtility
ADD requirements.txt /opt/VolUtility/requirements.txt

# Install PIP Requirements.
RUN cd /opt/VolUtility && \
 pip install -r requirements.txt

 # Clean Up
RUN rm -rf ~/tmp_build
RUN apt-get remove -yq \
 automake \
 autopoint \
 gettext \
 autoconf \
 gettext \
 pkg-config \
 libtool
RUN sudo apt-get clean

# Setup and Run
USER volutility
WORKDIR /opt/VolUtility
ADD start.sh start.sh
RUN mkdir /opt/VolUtility/dbpath
RUN chmod 755 /opt/VolUtility/dbpath
CMD /bin/bash /opt/VolUtility/start.sh
