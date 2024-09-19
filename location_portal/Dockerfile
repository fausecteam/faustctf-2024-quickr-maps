FROM faust.cs.fau.de:5000/location_portal_deps
#FROM localhost/test/location_portal_deps

WORKDIR /location_portal/db
RUN touch db.sqlite
WORKDIR /location_portal
COPY ./src .

CMD ["python", "-m", "flask", "--app", "/location_portal/", "run", "--host=::", "--port=4241"]
