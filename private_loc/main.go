package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Item struct {
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Tag       string  `json:"tag"`
	Timestamp int64   `json:"timestamp"`
	Owner     string  `json:"owner"`
}

var db *bolt.DB

const (
	locationStoreBucket = "LocationStore"
	sharingStoreBucket  = "SharingStore"
)

func setupBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(locationStoreBucket))
		if err != nil {
			return fmt.Errorf("Error during creation of bucket: %s", err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte(sharingStoreBucket))
		if err != nil {
			return fmt.Errorf("Error during creation of bucket: %s", err)
		}

		return nil
	})
}

func main() {
	var err error
	db, err = bolt.Open("private.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if setupBuckets(db) != nil {
		log.Fatalf("Fehler beim Öffnen der Datenbank: %v", err)
	}

	http.HandleFunc("/location/{id}", hanldeLocation)
	http.HandleFunc("/share/{id}", handleShare)
	log.Println("Server is running on port 4242...")
	log.Fatal(http.ListenAndServe(":4242", nil))
}

func hanldeLocation(w http.ResponseWriter, r *http.Request) {
	log.Println("HANDLE location:", r.URL)

	switch r.Method {
	case "GET":
		getLocations(w, r)
	case "POST":
		addLocation(w, r)
	default:
		w.WriteHeader(405)
	}
}

func handleShare(w http.ResponseWriter, r *http.Request) {
	log.Println("HANDLE share:", r.URL)

	switch r.Method {
	case "POST":
		queryParams := r.URL.Query()
		if queryParams.Has("receiver") {
			shareLocation(r.PathValue("id"), queryParams.Get("receiver"))
			w.WriteHeader(201)
		}
		fallthrough
	default:
		w.WriteHeader(405)
	}
}

func addLocation(w http.ResponseWriter, r *http.Request) {
	userId := r.PathValue("id")
	log.Println("adding to ", userId)
	var timestamp int64

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Restore the request body so it can be read again later
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Decode JSON body
	// Try to decode as a single item first
	var singleItem Item
	err = json.Unmarshal(bodyBytes, &singleItem)
	if err == nil {
		// Try to decode as a single item first
		log.Println("Received single Item", string(bodyBytes))
		timestamp, err = storeLocations([]Item{singleItem}, userId)
	} else {
		var jsonbody []Item
		err = json.Unmarshal(bodyBytes, &jsonbody)
		if err != nil {
			log.Println("Received", string(bodyBytes))
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		log.Println("Received ", len(jsonbody), "Items")
		timestamp, err = storeLocations(jsonbody, userId)
	}

	if err != nil {
		log.Printf("[ERROR] during dbGetLocations: %v", err)
		w.WriteHeader(500)
		return
	}

	t := strconv.Itoa(int(timestamp))

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(t))

}

func getLocations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	idString := r.PathValue("id")

	locs, err := gatherLocations(idString)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	json.NewEncoder(w).Encode(locs)
	w.WriteHeader(200)
}

func storeLocations(locations []Item, userId string) (int64, error) {
	timestamp := time.Now().UnixMilli()

	// start transaction
	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(locationStoreBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket %q not found", locationStoreBucket)
		}

		// load bucket if it exists
		var storedLocations []Item
		existingData := bucket.Get([]byte(userId))
		if existingData != nil {
			err := json.Unmarshal(existingData, &storedLocations)
			if err != nil {
				return fmt.Errorf("Error while unmarshalling location bucket: %v", err)
			}
		} else {
			storedLocations = make([]Item, 0)
		}
		log.Println("EXISTING DATA:", len(storedLocations))
		log.Println("ADDING   DATA:", len(locations))
		// add locations to list
		for _, v := range locations {
			v.Timestamp = timestamp
			v.Owner = userId
			storedLocations = append(storedLocations, v)
		}

		log.Println("STORING  DATA:", len(storedLocations))

		// pepare storing data
		updatedData, err := json.Marshal(storedLocations)
		if err != nil {
			return fmt.Errorf("Error while marshalling data: %v", err)
		}

		// store data in db
		err = bucket.Put([]byte(userId), updatedData)
		if err != nil {
			return fmt.Errorf("Error during : %v", err)
		}

		log.Println("STORED to location[", userId, "]")
		log.Println("STORED at:", timestamp)

		return nil
	})

	if err != nil {
		return -1, err
	}

	return timestamp, nil
}

func gatherLocations(userId string) ([]Item, error) {
	shares, err := dbGetShares(userId)

	if err != nil {
		return nil, err
	}

	// create final list, that will be returned (if no error occurs)
	ret := make([]Item, 0)

	// Get shared locations
	if len(shares) != 0 {

		for _, sharer := range shares {
			shared_locations, err := dbGetLocations(sharer)
			if err != nil {
				// simply ignore that one and do not die on error
				log.Printf("[ERROR]: Error during dbGetLocations: %v", err)
			} else {
				ret = append(ret, shared_locations...)
			}

		}
	}

	// Get own locations
	locations, err := dbGetLocations(userId)
	if err != nil {
		log.Printf("[ERROR]: Error during dbGetLocations: %v", err)
	} else {
		ret = append(ret, locations...)
	}

	return ret, nil
}

func shareLocation(userId string, receiver string) error {
	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(sharingStoreBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket %q not found", sharingStoreBucket)
		}

		// load existingData
		var storedSharings []string
		existingData := bucket.Get([]byte(receiver))
		if existingData != nil {
			err := json.Unmarshal(existingData, &storedSharings)
			if err != nil {
				return fmt.Errorf("Error while unmarshalling location bucket: %v", err)
			}
		} else {
			storedSharings = make([]string, 0)
		}

		// append new data
		storedSharings = append(storedSharings, userId)

		// store data
		updatedData, err := json.Marshal(storedSharings)
		if err != nil {
			return fmt.Errorf("Error while marshalling data: %v", err)
		}

		err = bucket.Put([]byte(receiver), updatedData)
		if err != nil {
			return fmt.Errorf("Error while marshalling data: %v", err)
		}

		log.Println("STORED share: sharing_store[" + receiver + "] appended" + userId)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func dbGetLocations(userId string) ([]Item, error) {
	var locations []Item

	err := db.View(func(tx *bolt.Tx) error {

		// Get Bucket
		bucket := tx.Bucket([]byte(locationStoreBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket not found %q", locationStoreBucket)
		}

		// Get Data by userId
		data := bucket.Get([]byte(userId))
		if data == nil {
			locations = make([]Item, 0)
		} else {
			// (JSON -> []Item)
			err := json.Unmarshal(data, &locations)
			if err != nil {
				return fmt.Errorf("Error during unmarshal: %v", err)
			}

		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return locations, nil
}

func dbGetShares(userId string) ([]string, error) {
	var shares []string

	err := db.View(func(tx *bolt.Tx) error {

		// Get Bucket
		bucket := tx.Bucket([]byte(sharingStoreBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket not found %q", sharingStoreBucket)
		}

		// Get Data by userId
		data := bucket.Get([]byte(userId))
		if data == nil {
			shares = make([]string, 0)
		} else {
			// (JSON -> string)
			err := json.Unmarshal(data, &shares)
			if err != nil {
				return fmt.Errorf("Error during unmarshal: %v", err)
			}

		}
		return nil

	})

	if err != nil {
		return nil, err
	}
	return shares, nil
}
