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
}


var db *bolt.DB

const storeBucket = "StoreBucket"
const bucketsKey = "location"

func setupBucket(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(storeBucket))
		if err != nil {
			return fmt.Errorf("Error during creation of bucket: %s", err)
		}
		return nil
	})
}

func main() {
	var err error
	db, err = bolt.Open("public.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	setupBucket(db)

	http.HandleFunc("/location/", hanldeLocation)
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

func addLocation(w http.ResponseWriter, r *http.Request) {
	var timestamp int64
	log.Println("adding location")

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Restore the request body so it can be read again later
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	log.Println("Received")

	// Decode JSON body
	// Try to decode as a single item first
	var singleItem Item
	err = json.Unmarshal(bodyBytes, &singleItem)
	if err == nil {
		// Try to decode as a single item first
		storeLocations([]Item{singleItem})
	} else {
		var jsonbody []Item
		err = json.Unmarshal(bodyBytes, &jsonbody)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		timestamp, err = storeLocations(jsonbody)
		if err != nil {
			w.WriteHeader(500)
			return
		}
	}
	t := strconv.Itoa(int(timestamp))

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(t))
}

func storeLocations(locations []Item) (int64, error) {
	timestamp := time.Now().UnixMilli()

	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(storeBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket %q not found", storeBucket)
		}

		var storedLocations []Item
		existingData := bucket.Get([]byte(bucketsKey))
		if existingData == nil {
			storedLocations = make([]Item, 0)
		} else {
			err := json.Unmarshal(existingData, &storedLocations)
			if err != nil {
				return fmt.Errorf("Error while unmarshalling buckets data: %v", err)
			}
		}

		for _, v := range locations {
			v.Timestamp = timestamp
			storedLocations = append(storedLocations, v)
		}
		// pepare storing data
		updatedData, err := json.Marshal(storedLocations)
		if err != nil {
			return fmt.Errorf("Error while marshalling data: %v", err)
		}

		// store data in db
		err = bucket.Put([]byte(bucketsKey), updatedData)
		if err != nil {
			return fmt.Errorf("Error during : %v", err)
		}

		return nil
	})

	if err != nil {
		return -1, err
	}
	log.Println("STORED to location:", len(locations))
	return timestamp, nil

}

func getLocations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	jsonString, err := dbGetLocations()
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}
	w.Write(jsonString)
}

func dbGetLocations() ([]byte, error) {
	var data []byte

	err := db.View(func(tx *bolt.Tx) error {

		// Get Bucket
		bucket := tx.Bucket([]byte(storeBucket))
		if bucket == nil {
			return fmt.Errorf("Bucket not found %q", storeBucket)
		}

		// Get Data
		data = bucket.Get([]byte(bucketsKey))
		if data == nil {
			data = []byte("[]")
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return data, nil
}
