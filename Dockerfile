# Build Stage
FROM ubuntu@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz \
    && rm -f go1.22.1.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Download and extract tools (Vita, Findomain)
RUN mkdir /tools/ \
    && wget -P /tools/ https://github.com/junnlikestea/vita/releases/download/0.1.16/vita-0.1.16-x86_64-unknown-linux-musl.tar.gz \
    && tar -xvf /tools/vita-0.1.16-x86_64-unknown-linux-musl.tar.gz -C /tools/ \
    && wget -P /tools/ https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && unzip /tools/findomain-linux.zip -d /tools/

# Clone Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /tools/Sublist3r

# Runtime Stage (final smaller image using Python slim)
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Copy Go binaries and tools from the build stage
COPY --from=build /root/go/bin /root/go/bin
COPY --from=build /tools/vita-0.1.16-x86_64-unknown-linux-musl/vita /usr/bin/vita
COPY --from=build /tools/findomain /usr/bin/findomain
COPY --from=build /tools/Sublist3r /tools/Sublist3r

# Install git and unzip (required for Sublist3r and Findomain)
# RUN apt update && apt install -y git unzip \
#     && apt clean && rm -rf /var/lib/apt/lists/*
# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.5.2
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL}

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Ensure correct permissions for findomain and Sublist3r
RUN chmod +x /usr/bin/findomain /tools/Sublist3r/sublist3r.py

# Copy necessary files
COPY subrecon subrecon
COPY scripts/findsubs.sh /app/findsubs.sh
RUN chmod +x /app/findsubs.sh

# Default command
CMD ["python3", "-m", "subrecon"]
