#!/usr/bin/env python3
import time
from typing import Tuple
from us_cities import US_CITIES
from models import Flag
from ctf_gameserver import checkerlib
from urllib.parse import urlparse, parse_qs
import logging
import random
import requests
import re
import string

import uuid
import logging
import json
import random
import requests

NAME_FRAGMENTS = ['shadow', 'whisper', 'zephyr', 'viper', 'classified', 'hawk', 'quicksilver', 'inferno', 'mirage', 'strike', 'jaguar', 'snare', 'specter', 'thunder', 'undercover', 'ghost', 'bolt', 'mission', 'magnificent', 'maverick', 'eagle', 'rogue', 'cryptic', 'raven', 'zero', 'enigmatic', 'delta', 'echo', 'covert', 'storm', 'omega', 'sniper',
                  'enigma', 'venom', 'lion', 'scorpion', 'agent', 'striker', 'lockpick', 'hunter', 'alpha', 'blade', 'underground', 'gale', 'silent', 'hacker', 'pursuit', 'tiger', 'serpent', 'black', 'wolf', 'onyx', 'stealth', 'cobra', 'guardian', 'sabre', 'bullet', 'phantom', 'operative', 'zenith', 'night', 'topsecret', 'falcon', 'shadowy', 'razor', 'dragon']
LOCATION_FRAGMENTS = ['cloister', 'forge', 'complex', 'station', 'vanguard', 'safehouse', 'base', 'sanctum', 'stronghold', 'nexus', 'tower', 'void', 'zenith', 'clearing', 'rendezvous', 'shadow', 'district', 'whisper', 'horizon', 'crypt', 'garrison', 'refuge', 'tunnel', 'crucible', 'raven', 'apex', 'covert', 'omega', 'citadel', 'archive', 'silo', 'alpha', 'solace', 'hollow', 'underpass', 'hydra', 'silent', 'quarry', 'hideout', 'cave', 'spire', 'temple',
                      'midnight', 'compound', 'zone', 'vault', 'lair', 'network', 'ghost', 'facility', 'quarantine', 'bunker', 'sector', 'chamber', 'serpent', 'lab', 'black', 'wolf', 'summit', 'haven', 'domain', 'scarlet', 'watchtower', 'perimeter', 'command', 'cove', 'grove', 'labyrinth', 'iron', 'outlook', 'encampment', 'phoenix', 'sanctuary', 'enclave', 'fortress', 'bastion', 'vista', 'delta', 'echo', 'outpost', 'den', 'asylum', 'griffon', 'blacksite', 'obsidian', 'dire']
EXPECTED_SERVERS = ['public_loc', 'private_loc']
EPSILON = 10e-4

# FLAG_OBSTRUCTION
RANDOM_LOCATIONS = 42  # setting this to 5 or smaller will result in no additions
OBSTRUCT_LOCATIONS = 1337


class LocationPortalChecker(checkerlib.BaseChecker):

    ########################## FLAG HELPER ##########################
    # TODO: nicht in die Datenbank legen
    # ist mehr Aufwand
    # TODO: cwd ist ggf. anders
    # passe es so an, dass es relativ zum python file läuft
    # Idee: worst case json in ein python string in city.py schreiben
    cities = US_CITIES

    def __float_eq(self, a, b):
        return abs(a-b) < EPSILON

    def __checkFlagHelper(self, coord_list, expected_coord, expected_timestamp, expected_owner) -> bool:
        for item in coord_list:
            if self.__float_eq(item["lat"], expected_coord["latitude"]) and \
                    self.__float_eq(item["lon"], expected_coord["longitude"]) and \
                    item["tag"] == expected_coord["tag"] and \
                    item["timestamp"] == expected_timestamp and \
                    item["owner"] == expected_owner:
                return True

        logging.error(" ++++ MISSING FLAG FRAGMENT ++++ ")
        logging.error(f"TIMESTAMP \texpected {expected_timestamp}")
        logging.error(f"OWNER\texpected {expected_owner}")
        logging.error(f"COORDS\texpected {expected_coord}")

        return False

    def __getOffset(self, tick):
        """generates a random offset for latitude, stores it and return (lat, lon)"""

        lat, lon = (0, 0)
        if self.cities == {}:
            lat = random.uniform(-90, 90)
            lon = random.uniform(-180, 180)
        else:
            city = random.choice(self.cities)
            lat = city["latitude"]
            lon = city["longitude"]

        checkerlib.store_state("offset" + str(tick), {"lat": lat, "lon": lon})
        return lat, lon

    #################### PORTAL HELPER ###########################

    def get_priv_server(self):
        return "private_loc"

    def get_pub_server(self):
        return "public_loc"

    def base_url(self):
        return f'http://[{self.ip}]:4241'

    def generate_agent_name(self):
        fragments = random.sample(NAME_FRAGMENTS, random.randint(0, 3))
        fragments.append(uuid.uuid4().hex)

        return "_".join(fragments)

    def generate_password(self):
        return uuid.uuid4().hex

    def generate_location(self, min_lat=-85.5, max_lat=85.5, min_lon=-160.5, max_lon=160.5, tag=None):
        assert min_lat < max_lat
        assert min_lon < max_lon

        if tag is None:
            tag = "-".join(random.sample(LOCATION_FRAGMENTS,
                           random.randint(0, 4)))
            tag += "-"
            tag += ''.join(random.choices(string.ascii_uppercase +
                                          string.digits, k=random.randint(4, 8)))

        lat = random.uniform(min_lat, max_lat)
        lon = random.uniform(min_lon, max_lon)

        return (tag, lat, lon)

    def generate_locations(self, n=20, min_lat=-85.5, max_lat=85.5, min_lon=-160.5, max_lon=160.5):
        return [self.generate_location(min_lat, max_lat, min_lon, max_lon) for _ in range(n)]

    def generate_credentials(self):
        return (self.generate_agent_name(), self.generate_password())

    def register(self, uname, pw):
        logging.info(f"Registering user {uname} with password {pw}")
        url = self.base_url()+'/register'
        form_data = {'agent_alias': uname, 'password': pw}
        r = requests.post(url, data=form_data)

        if "Registered new agent" in r.text:
            return True
        else:
            logging.error(f"Register failed for user: {uname}")
            return False

    def login(self, uname, pw) -> Tuple[bool, str, str]:
        logging.info(f"Logging in user {uname} with password {pw}")
        s = requests.Session()
        url = self.base_url()+'/login'
        form_data = {'agent_alias': uname, 'password': pw}
        r = s.post(url, data=form_data)

        if s.cookies.get('session') == None:
            logging.error(f"Failed to login user: {uname}")
            return (False, None, None)

        uid = re.findall(r"class=\"agent-id\">ID: ([0-9a-f\-]{36})", r.text)
        if len(uid) != 1:
            return (False, None, None)
        return (True, s, uid[0])

    def add_location(self, tag, lat, lon, session: requests.Session, server) -> bool:
        logging.info(f"Adding location {tag}: ({lat}, {lon})")
        url = self.base_url()+'/api/location/add'
        json_data = {"tag": tag,
                     "lat": lat,
                     "lon": lon}
        form_data = {'jsonData': json.dumps(json_data),
                     'server': server}
        r = session.post(url, data=form_data)

        if "Successfully added location" in r.text:
            # TOOD: use __extract_timestamp_from_url to return the created timestamp
            return True
        else:
            logging.error(f"Failed adding location {tag}: ({lat}, {lon})")
            return False

    def add_location_bulk(self, locations, session: requests.Session, server) -> Tuple[bool, int]:
        logging.info("Bulk Addtion of locations (in total {})".format(
            len(locations) if (type(locations) is list) else "unknown"
        ))
        url = self.base_url()+'/api/location/add/bulk'

        json_data = []

        for (tag, lat, lon) in locations:
            json_data.append({
                "tag": tag,
                "lat": lat,
                "lon": lon
            })

        form_data = {'jsonData': json.dumps(json_data),
                     'server': server}
        logging.debug(form_data)
        r = session.post(url, data=form_data)
        logging.info("response from 'api/location/add/bulk':\t" + r.text)

        if "Successfully added locations at timestamp:" in r.text:
            try:
                timestamp = int(r.text.split(":")[1])
                return True, timestamp
            except:
                return False, -1
        else:
            logging.error(f"Failed adding location {tag}: ({lat}, {lon})")
            return False, -1

    def get_locations(self, session: requests.Session, server):
        url = self.base_url()+'/api/locations?server='+server
        r = session.get(url)

        if r.status_code != 200:
            return False, []
        else:
            logging.debug('/api/locations?server='+server +
                          " - received " + str(len(r.json())) + "coords")
            # TODO: maybe check the json to be an array of elements
            logging.debug(r.json())
            return True, r.json()

    def share_location(self, session: requests.Session, server, receiver):
        logging.info(f"Sharing location with {receiver} on server {server}")
        url = self.base_url() + '/api/share'
        form_data = {'receiver': receiver,
                     'server': server}
        r = session.post(url, data=form_data)

        if "Successfully shared location" in r.text:
            return True
        else:
            logging.error(f"Failed to share location with {receiver}")
            return False

    def isLocationPresent(self, locationList, expectedLocationTuple):
        locations = {(loc['tag'], loc['lat'], loc['lon'])
                     for loc in locationList}
        return expectedLocationTuple in locations

    def check_service_portal(self):
        logging.info(f"----- Performing tests on location portal -----")
        # Check Registration
        logging.info("Checking portal registration")
        (uname, pw) = self.generate_credentials()
        if not self.register(uname, pw):
            logging.error("Registration failed")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Portal registration successful")

       # Check Login
        logging.info("Checking portal login")
        (success, session, uid) = self.login(uname, pw)
        if not success or uid is None:
            logging.error("Login failed")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Portal login successful")

        # check all servers present
        logging.info("Checking if all location servers present")
        r = session.get(self.base_url())
        pattern = r"selectServer\('([^']*)'\)"
        servers = re.findall(pattern, r.text)
        if not set(EXPECTED_SERVERS).issubset(servers):
            logging.error(
                f"Servers missing. Expected {EXPECTED_SERVERS} got {servers}")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("All location servers are present")
        logging.info(f"All tests on location portal successful")
        return checkerlib.CheckResult.OK

    def check_service_private(self):
        logging.info(
            f"----- Performing tests on server {self.get_priv_server()} -----")

        # Create user for tests
        (uname, pw) = self.generate_credentials()
        self.register(uname, pw)
        (success, session, uid) = self.login(uname, pw)
        if not success or uid is None:
            logging.error("Failed to create user for private server tests")
            return checkerlib.CheckResult.FAULTY

       # create 2nd user for sharing tests
        (uname_sharing, pw_sharing) = self.generate_credentials()
        self.register(uname_sharing, pw_sharing)
        (success, session_shr, uid_shr) = self.login(uname_sharing, pw_sharing)
        if not success:
            logging.error("Failed to create user for private server tests")
            return checkerlib.CheckResult.FAULTY

       # check add new location
        logging.info("Attempting to add single location")
        location_1 = (tag, lat, lon) = self.generate_location()
        if not self.add_location(tag, lat, lon, session, self.get_priv_server()):
            logging.error("Adding location failed")
            return checkerlib.CheckResult.FAULTY

        # check added location is present
        success, locations = self.get_locations(
            session, self.get_priv_server())
        if not success:
            return checkerlib.CheckResult.FAULTY

        if not self.isLocationPresent(locations, location_1):
            logging.error(
                f"Stored Location incorrect. Expected: {locations} to contain: {location_1}")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Single location successfully added")

       # check sharing
        logging.info("Attempting to share agents locations")
        if not self.share_location(session, self.get_priv_server(), uid_shr):
            logging.error("Sharing location failed")
            return checkerlib.CheckResult.FAULTY

        # check shared
        success, locations = self.get_locations(
            session_shr, self.get_priv_server())
        if not success:
            return checkerlib.CheckResult.FAULTY

        if not self.isLocationPresent(locations, location_1):
            logging.error(
                f"User didnt receive shared location. Expected: {location_1} got {tuple(locations[0].values())}")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Locations successfully shared")

        # check add new locations bulk
        logging.info("Attempting to bulk add locations")
        locations_bulk = [self.generate_location()
                          for _ in range(random.randint(3, 10))]
        success, _ = self.add_location_bulk(
            locations_bulk, session, self.get_priv_server())
        if not success:
            logging.error("Bulk adding locations failed")
            return checkerlib.CheckResult.FAULTY

        # check added new locations bulk
        success, locations = self.get_locations(
            session, self.get_priv_server())
        if not success:
            return checkerlib.CheckResult.FAULTY

        if len(locations) != len(locations_bulk)+1:
            logging.error(
                f"Incorrect number of locations present expected {len(locations_bulk+1)} got {len(locations)}")
            return checkerlib.CheckResult.FAULTY
        for location in locations_bulk:
            if not self.isLocationPresent(locations, location):
                logging.error(
                    f"Stored Locations incorrect. Expected: {locations} to contain: {location}")
                return checkerlib.CheckResult.FAULTY
        logging.info("Successfully added locations in bulk")

        # check timestamps
        logging.info("Validating location timestamps")
        location_2 = (tag, lat, lon) = self.generate_location()
        self.add_location(tag, lat, lon, session, self.get_priv_server())

        success, locations = self.get_locations(
            session, self.get_priv_server())
        if not success:
            return checkerlib.CheckResult.FAULTY

        location_1_timestamp = [location["timestamp"] for location in locations if
                                location["tag"] == location_1[0] and
                                location["lat"] == location_1[1] and
                                location["lon"] == location_1[2]]

        location_2_timestamp = [location["timestamp"] for location in locations if
                                location["tag"] == location_2[0] and
                                location["lat"] == location_2[1] and
                                location["lon"] == location_2[2]]


        if len(location_1_timestamp) == 0:
            logging.error(f"Couldnt find timestamp of location({location_1})")
            logging.error(f"Received locations:{locations}")
            return checkerlib.CheckResult.FAULTY
        elif len(location_2_timestamp) == 0:
            logging.error(f"Couldnt find timestamp of location({location_2})")
            logging.error(f"Received locations:{locations}")
            return checkerlib.CheckResult.FAULTY
        else:
            location_1_timestamp = location_1_timestamp[0]
            location_2_timestamp = location_2_timestamp[0]

        last_tick_timestamp = checkerlib.load_state(
            f"last_timestamp_{self.get_priv_server()}")
        if location_2_timestamp < location_1_timestamp or (last_tick_timestamp != None and location_1_timestamp <= last_tick_timestamp):
            logging.error(f"Unplausible timestamps found. Not increasing.")
            logging.error(
                f"1st location timestamp({location_1_timestamp}) should be smaller or equal than 2nd location timestamp({location_2_timestamp})")
            logging.error(
                f"last ticks location timestamp({last_tick_timestamp}) should be smaller than this ticks location timestamp({location_1_timestamp})")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Successfully validated location timestamps")

        checkerlib.store_state(
            f"last_timestamp_{self.get_priv_server()}", location_1_timestamp)

        logging.info(
            f"All tests on server {self.get_priv_server()} successful")
        return checkerlib.CheckResult.OK

    def check_service_public(self):
        logging.info(
            f"----- Performing tests on server {self.get_pub_server()} -----")

        session_nouser = requests.Session()
       # check add new location
        logging.info("Attempting to add single location")
        location_1 = (tag, lat, lon) = self.generate_location()
        if not self.add_location(tag, lat, lon, session_nouser, self.get_pub_server()):
            logging.error("Adding location failed")
            return checkerlib.CheckResult.FAULTY

        # check added location is present
        success, locations = self.get_locations(
            session_nouser, self.get_pub_server())
        if not success:
            return checkerlib.CheckResult.FAULTY
        if not self.isLocationPresent(locations, location_1):
            logging.error(
                f"Stored Location incorrect. Expected: {locations} to contain: {tag, lat, lon}")
            return checkerlib.CheckResult.FAULTY

        # Create user for test
        (uname, pw) = self.generate_credentials()
        self.register(uname, pw)
        (success, session, uid) = self.login(uname, pw)
        if not success or uid is None:
            logging.error("Failed to create user for public server tests")
            return checkerlib.CheckResult.FAULTY

        # check added location is present for logged in user
        success, locations = self.get_locations(session, self.get_pub_server())
        if not success:
            return checkerlib.CheckResult.FAULTY
        if not self.isLocationPresent(locations, location_1):
            logging.error(
                f"Stored Location incorrect. Expected: {locations} to contain: {location_1}")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Single location successfully added")

        # check timestamps
        logging.info("Validating location timestamps")
        location_2 = (tag, lat, lon) = self.generate_location()
        self.add_location(tag, lat, lon, session_nouser, self.get_pub_server())

        success, locations = self.get_locations(
            session_nouser, self.get_pub_server())
        if not success:
            return checkerlib.CheckResult.FAULTY

        location_1_timestamp = [location["timestamp"] for location in locations if
                                location["tag"] == location_1[0] and
                                location["lat"] == location_1[1] and
                                location["lon"] == location_1[2]]
        location_2_timestamp = [location["timestamp"] for location in locations if
                                location["tag"] == location_2[0] and
                                location["lat"] == location_2[1] and
                                location["lon"] == location_2[2]]

        if len(location_1_timestamp) == 0:
            logging.error(f"Couldnt find timestamp of location({location_1})")
            logging.error(f"Received locations:{locations}")
            return checkerlib.CheckResult.FAULTY
        elif len(location_2_timestamp) == 0:
            logging.error(f"Couldnt find timestamp of location({location_2})")
            logging.error(f"Received locations:{locations}")
            return checkerlib.CheckResult.FAULTY
        else:
            location_1_timestamp = location_1_timestamp[0]
            location_2_timestamp = location_2_timestamp[0]

        last_tick_timestamp = checkerlib.load_state(
            f"last_timestamp_{self.get_pub_server()}")

        if (location_2_timestamp < location_1_timestamp):
            logging.error(f"Unplausible timestamps found. Not increasing.")

            logging.error(
                f"1st location timestamp({location_1_timestamp}) should be smaller or equal than 2nd location timestamp({location_2_timestamp})")
            return checkerlib.CheckResult.FAULTY
        elif (last_tick_timestamp != None and location_1_timestamp <= last_tick_timestamp):
            logging.error(f"Unplausible timestamps found. Not increasing.")
            logging.error(
                f"last ticks location timestamp({last_tick_timestamp}) should be smaller than this ticks location timestamp({location_1_timestamp})")
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info("Successfully validated location timestamps")

        checkerlib.store_state(
            f"last_timestamp_{self.get_pub_server()}", location_1_timestamp)

        logging.info(f"All tests on server {self.get_pub_server()} successful")
        return checkerlib.CheckResult.OK

    def place_flag(self, tick):
        flag_string = checkerlib.get_flag(tick)
        logging.info("[GEN]:%s\t %s", tick, flag_string)

        lat, lon = self.__getOffset(tick)
        flag = Flag(flag_string=flag_string, base_lat=lat, base_long=lon)

        # store flag
        # TODO: storing the flag object is quite expensiv (storage wise)
        # maybe optimize it
        checkerlib.store_state("flag" + str(tick), flag)

        # create username and password
        agent = self.generate_agent_name()
        password = self.generate_password()

        # register
        success = self.register(agent, password)
        if not success:
            return checkerlib.CheckResult.FAULTY

        # store credentials
        checkerlib.store_state("credentials" + str(tick), {
            "agent": agent,
            "password": password
        })

        # login
        success, session, uid = self.login(agent, password)
        if not success:
            logging.error("Failed to login user for flag placement")
            return checkerlib.CheckResult.FAULTY
        checkerlib.store_state("uid" + str(tick), uid)

        # store flag
        coords = flag.coords()

        # TODO: (optional) do sometimes bulk and sometimes add_location
        if True:
            success, timestamp = self.add_location_bulk(
                flag.coordsTuples(), session, "private_loc")
            if not success:
                logging.error("Bulk adding locations failed")
                return checkerlib.CheckResult.FAULTY
            checkerlib.store_state("timestamp" + str(tick), timestamp)
            pass
        else:
            for coord in coords:
                logging.info(coord)
                success = self.add_location(
                    tag=coord["tag"], lat=coord["latitude"], lon=coord["longitude"],
                    session=session,
                    server=self.get_priv_server())
                if not success:
                    return checkerlib.CheckResult.FAULTY

        checkerlib.set_flagid(data=str(uid))

        # TODO: include some noise to the flag
        # Teams might try to add noise anyways to protect themself
        # or obstruct others during the flag read.
        # "Easy" exploits will then fail to decode the flag and their
        # owners might think the vuln got patched.
        # Therefore, add noise directly, so that an adversary needs
        # to construct their attack accordingly

        # TODO: one could move this to part of the checker?
        if RANDOM_LOCATIONS > 5:
            locations = self.generate_locations(n=RANDOM_LOCATIONS)

            # add in multiple bulk requests:
            # do this by seperating batch in 3 non emtpy batches
            point1 = random.randint(1, RANDOM_LOCATIONS-3)
            point2 = random.randint(1, RANDOM_LOCATIONS-3)
            mid1, mid2 = sorted([point1, point2])
            if mid1 == mid2:
                mid2 += 2

            batch1 = locations[0: mid1]
            batch2 = locations[mid1: mid2]
            batch3 = locations[mid2:]

            for batch in [batch1, batch2, batch3]:
                success, _ = self.add_location_bulk(
                    batch, session, "private_loc")
                if not success:
                    logging.error(
                        "Bulk adding locations failed (random locations were rejected)")
                    return checkerlib.CheckResult.FAULTY

        if OBSTRUCT_LOCATIONS > 5:
            min_lat, max_lat = [flag.min_lat(), flag.max_lat()]
            min_lon, max_lon = [flag.min_lon(), flag.max_lon()]

            locations = self.generate_locations(
                n=OBSTRUCT_LOCATIONS, min_lat=min_lat, max_lat=max_lat, min_lon=min_lon, max_lon=max_lon)

            # add in multiple bulk requests:
            # do this by seperating batch in 3 non emtpy batches
            point1 = random.randint(1, OBSTRUCT_LOCATIONS-3)
            point2 = random.randint(1, OBSTRUCT_LOCATIONS-3)
            mid1, mid2 = sorted([point1, point2])
            if mid1 == mid2:
                mid2 += 2

            batch1 = locations[0: mid1]
            batch2 = locations[mid1: mid2]
            batch3 = locations[mid2:]

            for batch in [batch1, batch2, batch3]:
                success, _ = self.add_location_bulk(
                    batch, session, "private_loc")
                if not success:
                    logging.error(
                        "Bulk adding locations failed (random locations were rejected)")
                    return checkerlib.CheckResult.FAULTY

        return checkerlib.CheckResult.OK

    def check_flag(self, tick):
        agent_login = checkerlib.load_state("credentials"+str(tick))
        flag: Flag = checkerlib.load_state("flag"+str(tick))
        timestamp = checkerlib.load_state("timestamp" + str(tick))
        uid = checkerlib.load_state("uid" + str(tick))

        if agent_login is None or flag is None or timestamp is None or uid is None:
            logging.error(f"Missing state in tick {tick}! agent_login:{agent_login}, flag:{flag}, timestamp:{timestamp}, uid:{uid}")
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        agent = agent_login["agent"]
        password = agent_login["password"]

        # login
        success, session, actual_uid = self.login(agent, password)
        if (not success) or (not uid == actual_uid):
            return checkerlib.CheckResult.FLAG_NOT_FOUND

        # get locations
        success, actual = self.get_locations(
            session=session, server=self.get_priv_server())
        if not success:
            return checkerlib.CheckResult.FLAG_NOT_FOUND

        # TODO: This is slow (O(n*n))
        # make it faster by e.g. sorting by timestamp first
        for expected in flag.coords():
            found = self.__checkFlagHelper(coord_list=actual,
                                           expected_coord=expected,
                                           expected_timestamp=timestamp,
                                           expected_owner=uid)
            if not found:
                return checkerlib.CheckResult.FLAG_NOT_FOUND
        return checkerlib.CheckResult.OK

    def check_service(self):
        check_functions = [self.check_service_portal,
                           self.check_service_private, self.check_service_public]
        random.shuffle(check_functions)

        for function in check_functions:
            result = function()
            if result == checkerlib.CheckResult.FAULTY:
                return checkerlib.CheckResult.FAULTY

        return checkerlib.CheckResult.OK


if __name__ == '__main__':
    start = time.time_ns()
    checkerlib.run_check(LocationPortalChecker)
    diff = time.time_ns() - start
    logging.info(f"CHECKER time computed: {diff/(1000 * 1000)} ms")
