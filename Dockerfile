# promptshield HTTP sidecar: docker build -t promptshield . && docker run -p 8787:8787 promptshield
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.13-slim
LABEL org.opencontainers.image.source="https://github.com/kirtanbhatt10/promptshield" \
      org.opencontainers.image.description="Zero-dependency guardrail sidecar for LLM apps" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PROMPTSHIELD_HOST=0.0.0.0 PROMPTSHIELD_PORT=8787
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER 65534:65534
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8787/healthz').status != 200)"
ENTRYPOINT ["promptshield", "serve"]
