package server

import (
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type Server struct {
	server http.Server
}

func StartServer(port int, policyDir string) *Server {
	router := httprouter.New()
	router.ServeFiles("/*filepath", http.Dir(policyDir))

	server := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("localhost:%v", port),
	}
	go func() { server.ListenAndServe() }()
	return &Server{
		server: *server,
	}
}

func (s *Server) Close() {
	s.server.Close()
}
