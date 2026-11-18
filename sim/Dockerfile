FROM python:3.12-slim
WORKDIR /srv
COPY ieso_sim ./ieso_sim
USER nobody
ENTRYPOINT ["python", "-m", "ieso_sim"]
