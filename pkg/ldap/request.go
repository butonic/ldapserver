package ldap

import (
	"fmt"

	"github.com/lor00x/goldap/message"
)

type Request struct {
	// TODO add reference to map of messages, needed for abandon
	*message.LDAPMessage
	Done chan bool
	Conn *conn
}

func (r *Request) String() string {
	return fmt.Sprintf("MessageId=%d, %s", r.MessageID(), r.ProtocolOpName())
}

// Abandon close the Done channel, to notify handler's user function to stop any
// running process
func (r *Request) Abandon() {
	r.Done <- true
}

func (r *Request) GetAbandonRequest() message.AbandonRequest {
	return r.ProtocolOp().(message.AbandonRequest)
}

func (r *Request) GetSearchRequest() message.SearchRequest {
	return r.ProtocolOp().(message.SearchRequest)
}

func (r *Request) GetBindRequest() message.BindRequest {
	return r.ProtocolOp().(message.BindRequest)
}

func (r *Request) GetAddRequest() message.AddRequest {
	return r.ProtocolOp().(message.AddRequest)
}

func (r *Request) GetDeleteRequest() message.DelRequest {
	return r.ProtocolOp().(message.DelRequest)
}

func (r *Request) GetModifyRequest() message.ModifyRequest {
	return r.ProtocolOp().(message.ModifyRequest)
}

func (r *Request) GetCompareRequest() message.CompareRequest {
	return r.ProtocolOp().(message.CompareRequest)
}

func (r *Request) GetExtendedRequest() message.ExtendedRequest {
	return r.ProtocolOp().(message.ExtendedRequest)
}
