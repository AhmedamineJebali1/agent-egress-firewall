# The agent. Standard library only: no pip install, so the image builds the
# same way on any machine and the run never depends on a package index.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY app ./app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    python -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('/app/app', quiet=1) else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "app.harness", "--config", "A"]
