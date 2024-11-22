# When updating version make sure to check on semgrepignore file as well
FROM golang:1.22-alpine AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/buildapp
COPY . .
RUN PATH_TO_MODULE=`go list -m` && go build -o /analyzer

FROM aquasec/trivy
COPY --from=build /analyzer /analyzer
ENTRYPOINT []
CMD ["/analyzer", "dependency"]
