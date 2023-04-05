FROM scratch

COPY gotlsproxy gotlsproxy

ENTRYPOINT [ "/gotlsproxy" ]
