# some fingerprints yield:
# http: panic serving 127.0.0.1:51682: invalid WriteHeader code 0
# when using
# FROM scratch
# ...
FROM alpine:3.19

COPY gotlsproxy gotlsproxy

ENTRYPOINT [ "/gotlsproxy" ]
