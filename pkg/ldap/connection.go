package ldap

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/butonic/ldapserver/pkg/constants"
	"github.com/lor00x/goldap/message"
)

// Create new connection from rwc.
func (srv *Server) newConn(rwc net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
		br:     bufio.NewReader(rwc),
		bw:     bufio.NewWriter(rwc),
	}
	return c
}

func (c *conn) setState(nc net.Conn, state ConnState) {
	srv := c.server
	switch state {
	case StateNew:
		srv.trackConn(c, true)
	case StateClosed:
		srv.trackConn(c, false)
	}
	if state > 0xff || state < 0 {
		panic("internal error")
	}
	packedState := uint64(time.Now().Unix()<<8) | uint64(state)
	atomic.StoreUint64(&c.curState.atomic, packedState)
	if hook := srv.ConnState; hook != nil {
		hook(nc, state)
	}
}

func (c *conn) getState() (state ConnState, unixSec int64) {
	packedState := atomic.LoadUint64(&c.curState.atomic)
	return ConnState(packedState & 0xff), int64(packedState >> 8)
}

type conn struct {
	Count int
	// server is the server on which the connection arrived.
	// Immutable; never nil.
	server *Server
	// cancelCtx cancels the connection-level context.
	cancelCtx   context.CancelFunc
	rwc         net.Conn
	br          *bufio.Reader
	bw          *bufio.Writer
	chanOut     chan *message.LDAPMessage
	wg          sync.WaitGroup
	curState    struct{ atomic uint64 } // packed (unixtime<<8|uint8(ConnState))
	closing     chan bool               // TODO as state?
	requestList map[int]*Request
	mutex       sync.Mutex
	writeDone   chan bool
	rawData     []byte
}

func (c *conn) GetConn() net.Conn {
	return c.rwc
}

func (c *conn) GetRaw() []byte {
	return c.rawData
}

func (c *conn) SetConn(conn net.Conn) {
	c.rwc = conn
	c.br = bufio.NewReader(c.rwc)
	c.bw = bufio.NewWriter(c.rwc)
}

func (c *conn) GetMessageByID(messageID int) (*Request, bool) {
	if requestToAbandon, ok := c.requestList[messageID]; ok {
		return requestToAbandon, true
	}
	return nil, false
}

func (c *conn) Addr() net.Addr {
	return c.rwc.RemoteAddr()
}

func (c *conn) readPacket() (*messagePacket, error) {
	mP, err := readMessagePacket(c.br)
	c.rawData = make([]byte, len(mP.Bytes))
	copy(c.rawData, mP.Bytes)
	return mP, err
}

// Serve a new connection. An LDAP connection can have multiple concurrent requests
// See https://tools.ietf.org/html/rfc4511#section-3
// And https://tools.ietf.org/html/rfc4511#section-3.1
//
// > 3.1.  Operation and LDAP Message Layer Relationship
// >
// >    Protocol operations are exchanged at the LDAP message layer.  When
// >    the transport connection is closed, any uncompleted operations at the
// >    LDAP message layer are abandoned (when possible) or are completed
// >    without transmission of the response (when abandoning them is not
// >    possible).  Also, when the transport connection is closed, the client
// >    MUST NOT assume that any uncompleted update operations have succeeded
// >    or failed.
func (c *conn) serve() {
	// in the end close a
	defer func() {
		c.close()
		c.setState(c.rwc, StateClosed)
	}()

	c.closing = make(chan bool)
	/*
		TODO reimplement using c.server.Connstate
		if onc := c.server.OnNewConnection; onc != nil {
			if err := onc(c.rwc); err != nil {
				c.server.Logger.Error(err, "Error OnNewConnection")
				return
			}
		}
	*/

	// Create the ldap response queue to be writted to client (buffered to 20)
	// buffered to 20 means that If client is slow to handler responses, Server
	// Handlers will stop to send more respones
	c.chanOut = make(chan *message.LDAPMessage)
	c.writeDone = make(chan bool)
	// for each message in c.chanOut send it to client
	go func() {
		for msg := range c.chanOut {
			c.writeMessage(msg)
			if len(c.requestList) < 1 {
				c.setState(c.rwc, StateIdle)
			}
		}
		// when all messages are written we can close the writeDone channel
		close(c.writeDone)
	}()

	// Listen for server signal to shutdown
	go func() {
		for {
			select {
			case <-c.server.getDoneChan(): // server signals shutdown process
				// we need to tell the clients
				c.wg.Add(1)
				c.setState(c.rwc, StateActive)
				r := NewExtendedResponse(constants.LDAPResultUnwillingToPerform)
				r.SetDiagnosticMessage("server is about to stop")
				r.SetResponseName(constants.NoticeOfDisconnection)

				m := message.NewLDAPMessageWithProtocolOp(r)

				c.chanOut <- m
				c.setState(c.rwc, StateClosed) // TODO do we close or something else?
				c.wg.Done()
				c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
				return
			case <-c.closing: // client closes connection
				// we no longer need read the server done chan
				return
			}
		}
	}()

	c.requestList = make(map[int]*Request)

	for {

		if c.server.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.server.ReadTimeout))
		}
		if c.server.WriteTimeout != 0 {
			c.rwc.SetWriteDeadline(time.Now().Add(c.server.WriteTimeout))
		}

		//Read client input as a ASN1/BER binary message
		messagePacket, err := c.readPacket()
		if err == io.EOF {
			return
		}
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				c.server.Logger.Error(err, "Sorry client, I can not wait anymore (reading timeout) !", "conn", c.Count)
			} else {
				c.server.Logger.Error(err, "Error readMessagePacket")
			}
			return
		}

		// If we read any bytes off the wire, we're active.
		c.setState(c.rwc, StateActive)

		//Convert ASN1 binaryMessage to an LDAP Message
		msg, err := messagePacket.readMessage()

		if err != nil {
			c.server.Logger.Error(err, "Error reading Message", "bytes", messagePacket.Bytes)
			continue
		}
		c.server.Logger.V(3).Info("read message", "conn", c.Count, "op", msg.ProtocolOpName(), "msg", messagePacket)

		// TODO: Use a implementation to limit running request by client
		// solution 1 : when the buffered output channel is full, send a busy
		// solution 2 : when 10 client requests (goroutines) are running, send a busy message
		// And when the limit is reached THEN send a BusyLdapMessage

		// When message is an UnbindRequest, stop serving
		if _, ok := msg.ProtocolOp().(message.UnbindRequest); ok {
			return
		}

		// If client requests a startTls, do not handle it in a
		// goroutine, connection has to remain free until TLS is OK
		// @see RFC https://tools.ietf.org/html/rfc4511#section-4.14.1
		if req, ok := msg.ProtocolOp().(message.ExtendedRequest); ok {
			if req.RequestName() == constants.NoticeOfStartTLS {
				c.wg.Add(1)
				c.ProcessRequestMessage(&msg)
				continue
			}
		}

		// TODO: go/non go routine choice should be done in the ProcessRequestMessage
		// not in the client.serve func
		c.wg.Add(1)
		go c.ProcessRequestMessage(&msg)
	}

}

// close closes client,
// * stop reading from client
// * signals to all currently running request processor to stop
// * wait for all request processor to end
// * close client connection
// * signal to server that client shutdown is ok
func (c *conn) close() {
	c.server.Logger.V(3).Info("close()", "conn", c.Count)
	close(c.closing) // stop reading from the server done chan in serve()

	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
	c.server.Logger.V(3).Info("close() - stop reading from client", "conn", c.Count)

	// signals to all currently running request processor to stop
	c.mutex.Lock()
	for messageID, request := range c.requestList {
		c.server.Logger.V(3).Info("close() - sent abandon signal to request", "conn", c.Count, "msgid", messageID)
		go request.Abandon()
	}
	c.mutex.Unlock()
	c.server.Logger.V(3).Info("close() - Abandon signal sent to processors", "conn", c.Count)

	c.wg.Wait()      // wait for all current running request processor to end
	close(c.chanOut) // No more message will be sent to client, close chanOUT
	c.server.Logger.V(3).Info("close() - request processors ended", "conn", c.Count)

	<-c.writeDone // Wait for the last message sent to be written
	c.rwc.Close() // close client connection
	c.setState(c.rwc, StateClosed)
	//c.server.wg.Done() // signal to server that client shutdown is ok
	c.server.Logger.V(3).Info("close() - connection closed", "conn", c.Count)
}
func (c *conn) writeMessage(m *message.LDAPMessage) {
	data, _ := m.Write()
	c.server.Logger.V(3).Info("writing message", "conn", c.Count, "op", m.ProtocolOpName(), "msg", data.Bytes())
	c.bw.Write(data.Bytes())
	c.bw.Flush()
}

// ResponseWriter interface is used by an LDAP handler to
// construct an LDAP response.
type ResponseWriter interface {
	// Write writes the LDAPResponse to the connection as part of an LDAP reply.
	Write(po message.ProtocolOp)
}

type responseWriterImpl struct {
	chanOut   chan *message.LDAPMessage
	messageID int
}

func (w responseWriterImpl) Write(po message.ProtocolOp) {
	m := message.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	w.chanOut <- m
}

func (c *conn) ProcessRequestMessage(msg *message.LDAPMessage) {
	defer c.wg.Done()

	var r Request
	r = Request{
		// TODO add reference to map of messages
		LDAPMessage: msg,
		Done:        make(chan bool, 2),
		Conn:        c,
	}

	c.registerRequest(&r)
	defer c.unregisterRequest(&r)

	// create a new ResponseWriter that will append messages to the c.chanOut
	var w responseWriterImpl
	w.chanOut = c.chanOut
	w.messageID = r.MessageID().Int()

	c.server.Handler.ServeLDAP(w, &r)
}

func (c *conn) registerRequest(m *Request) {
	c.mutex.Lock()
	c.requestList[m.MessageID().Int()] = m
	c.mutex.Unlock()
}

func (c *conn) unregisterRequest(m *Request) {
	c.mutex.Lock()
	delete(c.requestList, m.MessageID().Int())
	c.mutex.Unlock()
}
