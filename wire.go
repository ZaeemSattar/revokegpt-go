package revokegpt

import (
	"time"
)

// The wire form of a request: a map of the protocol's camelCase names. A zero value is left out.

type wireObj = map[string]any

func put(m wireObj, key string, v string) {
	if v != "" {
		m[key] = v
	}
}

func putStrings(m wireObj, key string, v []string) {
	if v != nil {
		l := make([]any, len(v))
		for i, s := range v {
			l[i] = s
		}
		m[key] = l
	}
}

func putFloat(m wireObj, key string, v *float64) {
	if v != nil {
		m[key] = *v
	}
}

func putBool(m wireObj, key string, v *bool) {
	if v != nil {
		m[key] = *v
	}
}

// rfc3339 is byte-identical to Date.toISOString() of the reference: milliseconds (truncated) and Z.
func rfc3339(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func putTime(m wireObj, key string, v *time.Time) {
	if v != nil {
		m[key] = rfc3339(*v)
	}
}

func (a AccountRef) put(m wireObj) {
	put(m, "accountId", a.AccountID)
	put(m, "hashedAccountId", a.HashedAccountID)
}

func (u UserInfo) wire() wireObj {
	m := wireObj{}
	u.AccountRef.put(m)
	putTime(m, "createAccountTime", u.CreateAccountTime)
	if u.UserIDs != nil {
		l := make([]any, len(u.UserIDs))
		for i, id := range u.UserIDs {
			e := wireObj{}
			put(e, "email", id.Email)
			put(e, "phoneNumber", id.PhoneNumber)
			put(e, "username", id.Username)
			l[i] = e
		}
		m["userIds"] = l
	}
	return m
}

func (a AccountVerification) wire() wireObj {
	m := wireObj{}
	l := make([]any, len(a.Endpoints))
	for i, e := range a.Endpoints {
		w := wireObj{}
		put(w, "emailAddress", e.EmailAddress)
		put(w, "phoneNumber", e.PhoneNumber)
		l[i] = w
	}
	m["endpoints"] = l
	put(m, "languageCode", a.LanguageCode)
	return m
}

func (a Address) wire() wireObj {
	m := wireObj{}
	put(m, "recipient", a.Recipient)
	putStrings(m, "address", a.Address)
	put(m, "locality", a.Locality)
	put(m, "administrativeArea", a.AdministrativeArea)
	put(m, "regionCode", a.RegionCode)
	put(m, "postalCode", a.PostalCode)
	return m
}

func (u TransactionUser) wire() wireObj {
	m := wireObj{}
	put(m, "accountId", u.AccountID)
	put(m, "creationMs", u.CreationMS)
	put(m, "email", u.Email)
	putBool(m, "emailVerified", u.EmailVerified)
	put(m, "phoneNumber", u.PhoneNumber)
	putBool(m, "phoneVerified", u.PhoneVerified)
	return m
}

func (i TransactionItem) wire() wireObj {
	m := wireObj{}
	put(m, "name", i.Name)
	putFloat(m, "value", i.Value)
	if i.Quantity != nil {
		m["quantity"] = *i.Quantity
	}
	put(m, "merchantAccountId", i.MerchantAccountID)
	return m
}

func (g GatewayInfo) wire() wireObj {
	m := wireObj{}
	put(m, "name", g.Name)
	put(m, "gatewayResponseCode", g.GatewayResponseCode)
	put(m, "avsResponseCode", g.AVSResponseCode)
	put(m, "cvvResponseCode", g.CVVResponseCode)
	return m
}

func (t TransactionData) wire() wireObj {
	m := wireObj{}
	put(m, "transactionId", t.TransactionID)
	put(m, "paymentMethod", t.PaymentMethod)
	put(m, "cardBin", t.CardBin)
	put(m, "cardLastFour", t.CardLastFour)
	put(m, "currencyCode", t.CurrencyCode)
	putFloat(m, "value", t.Value)
	putFloat(m, "shippingValue", t.ShippingValue)
	if t.ShippingAddress != nil {
		m["shippingAddress"] = t.ShippingAddress.wire()
	}
	if t.BillingAddress != nil {
		m["billingAddress"] = t.BillingAddress.wire()
	}
	if t.User != nil {
		m["user"] = t.User.wire()
	}
	if t.Merchants != nil {
		l := make([]any, len(t.Merchants))
		for i, u := range t.Merchants {
			l[i] = u.wire()
		}
		m["merchants"] = l
	}
	if t.Items != nil {
		l := make([]any, len(t.Items))
		for i, it := range t.Items {
			l[i] = it.wire()
		}
		m["items"] = l
	}
	if t.GatewayInfo != nil {
		m["gatewayInfo"] = t.GatewayInfo.wire()
	}
	return m
}

func (e TransactionEvent) wire() wireObj {
	m := wireObj{"eventType": e.EventType}
	put(m, "reason", e.Reason)
	putFloat(m, "value", e.Value)
	put(m, "eventTime", e.EventTime)
	return m
}

func (a AnnotateInput) wire() wireObj {
	m := wireObj{}
	put(m, "annotation", a.Annotation)
	putStrings(m, "reasons", a.Reasons)
	a.AccountRef.put(m)
	if a.TransactionEvent != nil {
		m["transactionEvent"] = a.TransactionEvent.wire()
	}
	return m
}
