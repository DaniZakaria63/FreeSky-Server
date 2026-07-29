FROM rust:1.85-slim-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p freesky-server
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd -r freesky && useradd -r -g freesky -d /data -s /sbin/nologin freesky
COPY --from=builder /app/target/release/freesky-server /usr/local/bin/freesky-server
RUN mkdir -p /data && chown freesky:freesky /data
VOLUME /data
EXPOSE 3000 9443
USER freesky
WORKDIR /data
CMD ["freesky-server"]
