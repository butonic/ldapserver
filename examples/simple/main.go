// Listen to 10389 port for LDAP Request
// and route bind request to the handleBind func
package main

import (
	stdlog "log"
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/butonic/ldapserver/pkg/constants"
	"github.com/butonic/ldapserver/pkg/ldap"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
)

var log logr.Logger

func main() {

	// max verbosity
	stdr.SetVerbosity(10)
	log = stdr.New(stdlog.New(os.Stderr, "", stdlog.LstdFlags|stdlog.Lshortfile))

	//Create a new LDAP Server
	server := ldap.NewServer(
		// listen on 10389
		ldap.Addr("127.0.0.1:10389"),
		ldap.Logger(log),
	)

	routes := ldap.NewRouteMux(
		ldap.Logger(log),
	)
	routes.Bind(handleBind)
	server.Handle(routes)

	// listen on 10389
	go server.ListenAndServe()

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Shutdown(context.Background())
}

// handleBind return Success if login == mysql
func handleBind(w ldap.ResponseWriter, m *ldap.Request) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(constants.LDAPResultSuccess)

	if string(r.Name()) == "login" {
		// w.Write(res)
		return
	}

	log.Info("Bind failed", "user", string(r.Name()), "pass", string(r.AuthenticationSimple()))
	res.SetResultCode(constants.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}
