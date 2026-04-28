FROM debian:stable AS build

WORKDIR /usr/local/src

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		g++ \
		libcurl4-openssl-dev \
		libperl-dev \
		libssl-dev \
		make

RUN curl -L https://sourceforge.net/projects/exiftool/files/Image-ExifTool-13.41.tar.gz/download > exiftool.tgz \
	&& tar -xf exiftool.tgz \
	&& cd Image-ExifTool-* \
	&& perl Makefile.PL \
	&& make install

WORKDIR /app

COPY . ./

RUN make all

RUN --mount=type=secret,id=apikey,env=SIGNMYDATA_APIKEY \
	--mount=type=secret,id=signid,env=SIGNMYDATA_ID \
	cd tests \
	&& ./test-all-ci.sh

FROM debian:stable-slim AS publish

WORKDIR /root

RUN apt-get update \
	&& apt-get install --no-install-recommends -y libcurl4-openssl-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build "/app/bin/sealtool" "/usr/local/bin/"

ENTRYPOINT ["/usr/local/bin/sealtool"]

