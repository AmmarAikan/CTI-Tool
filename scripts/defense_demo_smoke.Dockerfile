FROM mcr.microsoft.com/playwright/python:v1.62.0-noble

RUN python -m pip install --no-cache-dir playwright==1.62.0

WORKDIR /workspace
COPY scripts/defense_demo_smoke.py /workspace/scripts/defense_demo_smoke.py

USER pwuser
