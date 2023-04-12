package app

import (
	"log"
	"net/http"
)

type Handlers struct {
	DidDocumentHandler *DidDocumentHandler
}

func (s *Handlers) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/1.0/identifiers/", s.DidDocumentHandler.Get)
	mux.HandleFunc("/1.0/gist", s.DidDocumentHandler.GetGist)
	mux.HandleFunc("/dns/", s.DidDocumentHandler.GetByDNSDomain)
	mux.HandleFunc("/ens/", s.DidDocumentHandler.GetByENSDomain)
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"OK"}`))
		if err != nil {
			log.Println("failed send body response")
		}
	})

	return mux
}
