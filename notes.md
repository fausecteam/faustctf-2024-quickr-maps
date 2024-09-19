# Document Title

            -> public server
-> web server 
            -> private server
            
            
            

# Webserver -> python
- Agenten Portal Features
  - Register/Login/Logout
  - Auswahl der location service Instanz
  - Karte/Liste aller seiner Locations
  - Karte/Liste aller geteileten Locations

- Seiten:
  - index
  - register/login/logout
  - Location overview -> public/private toggle
  - Add/Edit/Delete location view
  - Share Location view


# public location server -> go
## Features
- add location
- get all locations

# location server -> go
## Features required
- mehrere locations speichern & abrufen
- location teilen -> 
- interface
POST /location?agent-id=1 -> adds new location
GET /locations/1 -> gets all locations
POST /share?agent-id=1&receiver-id=2 -> share locations of agent with receiver
GET /share?agent-id=1 -> gets all locations shared with agent

## Features additional
- export locations as QR Code


# Interfaces

/test
{"data": "passed"}
