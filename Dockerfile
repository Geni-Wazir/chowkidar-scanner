FROM kalilinux/kali-rolling

WORKDIR /opt/scanner

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    python3 \
    python3.11-venv \
    nmap \
    testssl.sh \
    sublist3r \
    nuclei \
    wpscan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"


COPY . /opt/scanner

RUN pip install --no-cache-dir -r requirements.txt