FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ieso_investigator ./ieso_investigator
USER nobody
ENTRYPOINT ["python", "-m", "ieso_investigator"]
