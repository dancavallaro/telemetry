FROM golang:1.22.5-bookworm as base

WORKDIR /
RUN git clone https://github.com/dancavallaro/telemetry.git
RUN cd telemetry && \
    go build -o serial_logger cmd/serial_logger/main.go && \
    go build -o heartbeats cmd/heartbeats/main.go


FROM busybox:1.36.1 as serial_logger

WORKDIR /
COPY --from=base /telemetry/serial_logger /serial_logger

ENTRYPOINT ["/serial_logger"]


FROM debian:bookworm-slim as heartbeats

WORKDIR /

RUN apt update && apt-get install -y ca-certificates

COPY --from=base /telemetry/heartbeats /heartbeats

ENTRYPOINT ["/heartbeats"]
