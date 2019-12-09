package ldap

import "github.com/lor00x/goldap/message"

func NewBindResponse(resultCode int) message.BindResponse {
	r := message.BindResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewResponse(resultCode int) message.LDAPResult {
	r := message.LDAPResult{}
	r.SetResultCode(resultCode)
	return r
}

func NewExtendedResponse(resultCode int) message.ExtendedResponse {
	r := message.ExtendedResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewCompareResponse(resultCode int) message.CompareResponse {
	r := message.CompareResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewModifyResponse(resultCode int) message.ModifyResponse {
	r := message.ModifyResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewDeleteResponse(resultCode int) message.DelResponse {
	r := message.DelResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewAddResponse(resultCode int) message.AddResponse {
	r := message.AddResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultDoneResponse(resultCode int) message.SearchResultDone {
	r := message.SearchResultDone{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultEntry(objectname string) message.SearchResultEntry {
	r := message.SearchResultEntry{}
	r.SetObjectName(objectname)
	return r
}
