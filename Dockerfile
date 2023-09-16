# Force distroless base to use current platform (most likely linux/amd64)
# which is needed since distroless/static is not available for linux/arm/v6
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static as distroless

FROM scratch
COPY --from=distroless / /
COPY cinodefs-analyzer /cinodefs-analyzer
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT [ "/cinodefs-analyzer" ]
