package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type PrevParty int

const (
	ClientParty PrevParty = iota + 1
	ServerParty
)

type Slice struct {
	Values    []byte    `json:"values"`
	Ctx       string    `json:"ctx"`
	Round     int       `json:"round"`
	PrevParty PrevParty `json:"prev_party" default:"0"`
}

var dkgPool []Slice

func mpcHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var sliceFromClient Slice
	err = json.Unmarshal(body, &sliceFromClient)
	if err != nil {
		http.Error(w, "Error unmarshalling JSON", http.StatusBadRequest)
		return
	}

	sliceFromClient.PrevParty = ServerParty

	found := false
	for i, d := range dkgPool {
		if d.Ctx == sliceFromClient.Ctx {
			// Update the Slice in dkgPool
			dkgPool[i] = sliceFromClient
			found = true
			break
		}
	}

	if !found {
		// Append sliceFromClient to dkgPool
		dkgPool = append(dkgPool, sliceFromClient)
	}

	if sliceFromClient.Ctx == "" {
		http.Error(w, "Invalid Slice Context", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(sliceFromClient)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
func poolsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	response, err := json.Marshal(dkgPool)
	if err != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
func testMockServer() {
	//dkgPool := []Slice{}
	mpcContext := Slice{
		Values: []byte{0x01, 0x02, 0x03},
		Ctx:    "initial",
		Round:  0,
	}

	dkgPool = append(dkgPool, mpcContext)

	http.HandleFunc("/slice", mpcHandler)
	http.HandleFunc("/pools", poolsHandler)

	fmt.Println("Starting server on port 8000")
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatal(err)
	}
}
