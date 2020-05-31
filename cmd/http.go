package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"time"
)

const (
	// Time allowed to read the next pong message from the client.
	pongWait = 60 * time.Second

	// Send pings to client with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Time allowed to write the file to the client.
	writeWait = 10 * time.Second
)

func (p *Parser) serveHTTP() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fn := "html/index.html"
		t, err := template.ParseFiles(fn)
		if err != nil {
			fmt.Fprint(w, "Error parsing template file:", fn, " with error:", err)
			return
		}
		t.Execute(w, map[string]string{"ServerHost": r.Host})
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := WS.Upgrade(w, r, nil)
		if err != nil {
			if _, ok := err.(websocket.HandshakeError); !ok {
				log.Println(err)
			}
			return
		}

		go p.WSwriter(conn)
		p.WSreader(conn)

	})
	log.WithFields(log.Fields{"type": "HTTPServer", "lister": *Listen}).Info("Staring HTTP server")

	http.ListenAndServe(*Listen, nil)
}

func (p *Parser) WSreader(ws *websocket.Conn) {
	defer ws.Close()
	ws.SetReadLimit(512)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (p *Parser) WSwriter(ws *websocket.Conn) {
	pingTicker := time.NewTicker(pingPeriod)
	dataTicker := time.NewTicker(100 * time.Millisecond)

	var lastID uint32

	defer func() {
		pingTicker.Stop()
		dataTicker.Stop()
		ws.Close()
	}()

	for {
		select {
		case <-pingTicker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		case <-dataTicker.C:
			// Check for LastUpdate
			p.Queue.RLock()
			if p.Queue.Id > lastID {
				l := 0
				if (p.Queue.Id - lastID) < uint32(len(p.Queue.List)) {
					l = len(p.Queue.List) - int(p.Queue.Id - lastID)
				}
				data :=p.Queue.List[l:]
				lastID = p.Queue.Id
				p.Queue.RUnlock()

				output, err := json.Marshal(data)
				if err != nil {
					log.WithFields(log.Fields{"type": "json-marshal", "module": "WSWriter"}).Error(err)
					return
				}

				ws.SetWriteDeadline(time.Now().Add(writeWait))
				if err := ws.WriteMessage(websocket.TextMessage, []byte(output)); err != nil {
					return
				}
			} else {
				p.Queue.RUnlock()
			}
		}
	}
}
