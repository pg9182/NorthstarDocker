# syntax=docker/dockerfile:1
#
# docker buildx build --pull --platform linux/amd64 --target web --load --tag northstar:web .
# docker buildx build --pull --platform linux/amd64 --build-arg NS_VERSION=1.21.4 --load --tag northstar:latest --tag northstar:1 --tag northstar:1.21 --tag northstar:1.21.4 .

# the northstar runtime multiarch image to use
ARG NS_RUNTIME=ghcr.io/pg9182/northstar-runtime:latest

# the northstar release to download
ARG NS_VERSION=latest

# build nslaunch for the build platform
FROM --platform=$BUILDPLATFORM docker.io/golang:1.21 AS build-nslaunch-native
WORKDIR /src
COPY ./ /src/
RUN mkdir -p /opt/northstar/bin/
RUN CGO_ENABLED=0 go build -v -trimpath -o /opt/northstar/bin/nslaunch .

# build nslaunch for the target platform
FROM --platform=$BUILDPLATFORM docker.io/golang:1.21 AS build-nslaunch
ARG TARGETARCH
WORKDIR /src
COPY ./go.mod ./go.sum ./*.go /src/
RUN mkdir -p /opt/northstar/bin/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -v -trimpath -o /opt/northstar/bin/nslaunch .

# download northstar release
FROM --platform=$BUILDPLATFORM docker.io/golang:1.21 AS build-northstar
COPY --link --from=build-nslaunch-native /opt/northstar /opt/northstar
ENV NS_VERSION=${NS_VERSION}
RUN /opt/northstar/bin/nslaunch download

# web image
FROM --platform=$TARGETPLATFORM ${NS_RUNTIME} AS web
COPY --link --from=build-nslaunch /opt/northstar /opt/northstar
ENV NS_VERSION=${NS_VERSION}
ENTRYPOINT ["/opt/northstar/bin/nslaunch"]
CMD ["run"]

# offline image
FROM web
COPY --link --from=build-northstar /opt/northstar/files /opt/northstar/files
