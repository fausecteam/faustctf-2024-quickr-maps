from us_cities import US_CITIES
from PIL import Image
from pyzbar.pyzbar import decode

import cv2
import numpy as np
import qrcode
import random
import uuid
import string

CITIES = US_CITIES


LOCATION_FRAGMENTS = ['cloister', 'forge', 'complex', 'station', 'vanguard', 'safehouse', 'base', 'sanctum', 'stronghold', 'nexus', 'tower', 'void', 'zenith', 'clearing', 'rendezvous', 'shadow', 'district', 'whisper', 'horizon', 'crypt', 'garrison', 'refuge', 'tunnel', 'crucible', 'raven', 'apex', 'covert', 'omega', 'citadel', 'archive', 'silo', 'alpha', 'solace', 'hollow', 'underpass', 'hydra', 'silent', 'quarry', 'hideout', 'cave', 'spire', 'temple',
                      'midnight', 'compound', 'zone', 'vault', 'lair', 'network', 'ghost', 'facility', 'quarantine', 'bunker', 'sector', 'chamber', 'serpent', 'lab', 'black', 'wolf', 'summit', 'haven', 'domain', 'scarlet', 'watchtower', 'perimeter', 'command', 'cove', 'grove', 'labyrinth', 'iron', 'outlook', 'encampment', 'phoenix', 'sanctuary', 'enclave', 'fortress', 'bastion', 'vista', 'delta', 'echo', 'outpost', 'den', 'asylum', 'griffon', 'blacksite', 'obsidian', 'dire']

class Flag:
    BOX_SIZE = 1
    BORDER = 0

    def generate_tag(self):
        tag = "-".join(random.sample(LOCATION_FRAGMENTS, random.randint(0, 4)))
        tag += "-"
        tag += ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(4, 8)))
        return tag

    def __init__(self, flag_string="FAU{1137}", base_lat=0, base_long=0, shift_lat=0.1, shift_long=0.1, random_city=False):
        if random_city:
            city = random.choice(CITIES)
            print(city)
            base_long = city["longitude"]
            base_lat = city["latitude"]

        # self.flag = self.__gen_flag(flag_content)
        self.flag = flag_string
        # self.qr = Flag.flag_to_qrcode(self.flag)
        self.bit_map = Flag.flag_to_bitmap(self.flag)

        self.base_lat = base_lat
        self.base_long = base_long
        self.shift_lat = shift_lat
        self.shift_long = shift_long

        self.__coords = self.__calculate_coordinates(
            self.bit_map,
            self.base_lat,
            self.base_long,
            self.shift_lat,
            self.shift_long
        )

        self.__coords = [
            {"tag": self.generate_tag(),
             "latitude": c[0],
             "longitude": c[1]
             } for c in self.__coords]

    def coords(self) -> list:
        return self.__coords

    def min_lat(self) -> int:
        return min([x["latitude"] for x in self.__coords])

    def max_lat(self) -> int:
        return max([x["latitude"] for x in self.__coords])

    def min_lon(self) -> int:
        return min([x["longitude"] for x in self.__coords])

    def max_lon(self) -> int:
        return max([x["longitude"] for x in self.__coords])

    def coordsTuples(self) -> list:
        return [(c["tag"], c["latitude"], c["longitude"]) for c in self.__coords]

    def __calculate_coordinates(self, bitmap, base_latitude, base_longitude, shift_lat, shift_long):
        coordinates = []

        for y, row in enumerate(bitmap):
            for x, pixel in enumerate(row):
                if pixel == 1:
                    latitude = base_latitude + shift_lat * y
                    longitude = base_longitude + shift_long * x
                    coordinates.append((latitude, longitude))

        return coordinates

    @staticmethod
    def flag_to_qrcode(flag, show=False, path=None):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=Flag.BOX_SIZE,
            border=Flag.BORDER,
        )
        qr.add_data(flag)

        img = qr.make_image(fill_color="black", back_color="white")
        if show:
            img.show()
        if path is not None:
            img.save(path)
        return img

    @staticmethod
    def flag_to_bitmap(flag):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=Flag.BOX_SIZE,
            border=Flag.BORDER,
        )
        qr.add_data(flag)

        matrix = qr.get_matrix()
        converted_matrix = [[1 if cell else 0 for cell in row]
                            for row in matrix]

        return converted_matrix

    @staticmethod
    def bitmap_to_qr(bitmap, show=False):
        # Convert the bitmap to a NumPy array
        # inverte the values and scale it
        pixels = (1-np.array(bitmap)) * 255
        image = Image.fromarray(pixels.astype('uint8'), 'L')

        # Get the original dimensions
        original_width, original_height = image.size

        # Calculate new dimensions: each pixel will become a 4x4 block
        new_width = original_width * 16
        new_height = original_height * 16

        # Resize the image to the new dimensions
        enlarged_image = image.resize((new_width, new_height), Image.NEAREST)

        if show:
            enlarged_image.show()  # Show the image in a standard image viewer

        return enlarged_image

    @staticmethod
    def decode_qr_code_opencv(image_path):
        image = cv2.imread(image_path, 0)

        barcodes = decode(image)
        print(barcodes)
