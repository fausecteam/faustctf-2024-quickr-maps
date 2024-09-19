SERVICE := quickr-maps
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: build install

build:
	echo nothing to build

install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	# Remove dependency image from docker-compose
	yq -y 'del(.services."location_portal_deps") | del(.services."backend_loc_deps")' docker-compose.yml > $(DESTDIR)$(SERVICEDIR)/docker-compose.yml

	mkdir -p $(DESTDIR)$(SERVICEDIR)/location_portal/
	cp -r location_portal/* $(DESTDIR)$(SERVICEDIR)/location_portal/
	mkdir -p $(DESTDIR)$(SERVICEDIR)/private_loc/
	cp -r private_loc/* $(DESTDIR)$(SERVICEDIR)/private_loc/
	mkdir -p $(DESTDIR)$(SERVICEDIR)/public_loc/
	cp -r public_loc/* $(DESTDIR)$(SERVICEDIR)/public_loc/

	mkdir -p $(DESTDIR)/etc/systemd/system/faustctf.target.wants/
	ln -s /etc/systemd/system/docker-compose@.service $(DESTDIR)/etc/systemd/system/faustctf.target.wants/docker-compose@$(SERVICE).service

