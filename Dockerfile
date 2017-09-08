FROM alpine:3.5
COPY bin/assert-aws-iam-permissions /assert-aws-iam-permissions
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 9090
ENTRYPOINT ["/assert-aws-iam-permissions"]
