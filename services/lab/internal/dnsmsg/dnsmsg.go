// Package dnsmsg implements just enough of RFC 1035 wire format to run a
// policy-enforcing resolver and a small authoritative server. No third-party
// dependencies on purpose: the whole lab must build offline.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeTXT   = 16
	TypeAAAA  = 28

	ClassIN = 1

	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

var ErrMalformed = errors.New("malformed dns message")

// Question is the single question we care about (multi-question queries are
// not used in practice).
type Question struct {
	ID       uint16
	Name     string // lower-cased, no trailing dot
	Type     uint16
	Class    uint16
	QDEnd    int // offset just past the question section
	Raw      []byte
	Recursed bool
}

// TypeName renders a query type for logs.
func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeTXT:
		return "TXT"
	case TypeCNAME:
		return "CNAME"
	case TypeNS:
		return "NS"
	}
	return "TYPE?"
}

// ParseQuestion reads the header and first question of a query.
func ParseQuestion(buf []byte) (*Question, error) {
	if len(buf) < 12 {
		return nil, ErrMalformed
	}
	id := binary.BigEndian.Uint16(buf[0:2])
	flags := binary.BigEndian.Uint16(buf[2:4])
	qd := binary.BigEndian.Uint16(buf[4:6])
	if qd < 1 {
		return nil, ErrMalformed
	}
	name, off, err := readName(buf, 12)
	if err != nil {
		return nil, err
	}
	if off+4 > len(buf) {
		return nil, ErrMalformed
	}
	qtype := binary.BigEndian.Uint16(buf[off : off+2])
	qclass := binary.BigEndian.Uint16(buf[off+2 : off+4])
	return &Question{
		ID:       id,
		Name:     strings.ToLower(strings.TrimSuffix(name, ".")),
		Type:     qtype,
		Class:    qclass,
		QDEnd:    off + 4,
		Raw:      buf,
		Recursed: flags&0x0100 != 0,
	}, nil
}

// readName walks a (possibly compressed) domain name.
func readName(buf []byte, off int) (string, int, error) {
	var sb strings.Builder
	jumps := 0
	cur := off
	after := -1
	for {
		if cur >= len(buf) {
			return "", 0, ErrMalformed
		}
		l := int(buf[cur])
		if l == 0 {
			cur++
			if after == -1 {
				after = cur
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if cur+1 >= len(buf) {
				return "", 0, ErrMalformed
			}
			ptr := int(binary.BigEndian.Uint16(buf[cur:cur+2]) & 0x3FFF)
			if after == -1 {
				after = cur + 2
			}
			jumps++
			if jumps > 16 || ptr >= len(buf) {
				return "", 0, ErrMalformed
			}
			cur = ptr
			continue
		}
		if l > 63 || cur+1+l > len(buf) {
			return "", 0, ErrMalformed
		}
		sb.Write(buf[cur+1 : cur+1+l])
		sb.WriteByte('.')
		cur += 1 + l
		if sb.Len() > 255 {
			return "", 0, ErrMalformed
		}
	}
	return sb.String(), after, nil
}

// Labels splits a name into its labels.
func Labels(name string) []string {
	name = strings.Trim(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func header(q *Question, rcode int, ancount int, authoritative bool) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], q.ID)
	var flags uint16 = 0x8000 // QR
	if authoritative {
		flags |= 0x0400 // AA
	}
	if q.Recursed {
		flags |= 0x0100 // RD
	}
	flags |= 0x0080 // RA
	flags |= uint16(rcode & 0xF)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(ancount))
	return out
}

func questionBytes(q *Question) []byte {
	return q.Raw[12:q.QDEnd]
}

// Respond builds an answer-free reply carrying the given rcode.
func Respond(q *Question, rcode int, authoritative bool) []byte {
	out := header(q, rcode, 0, authoritative)
	return append(out, questionBytes(q)...)
}

// AnswerA builds a NOERROR reply with one or more A records.
func AnswerA(q *Question, ips []net.IP, ttl uint32, authoritative bool) []byte {
	var rrs []byte
	n := 0
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		rr := make([]byte, 0, 16)
		rr = append(rr, 0xC0, 0x0C) // pointer to the question name
		rr = binary.BigEndian.AppendUint16(rr, TypeA)
		rr = binary.BigEndian.AppendUint16(rr, ClassIN)
		rr = binary.BigEndian.AppendUint32(rr, ttl)
		rr = binary.BigEndian.AppendUint16(rr, 4)
		rr = append(rr, v4...)
		rrs = append(rrs, rr...)
		n++
	}
	out := header(q, RcodeNoError, n, authoritative)
	out = append(out, questionBytes(q)...)
	return append(out, rrs...)
}

// AnswerTXT builds a NOERROR reply with a single TXT record.
func AnswerTXT(q *Question, text string, ttl uint32, authoritative bool) []byte {
	if len(text) > 255 {
		text = text[:255]
	}
	rr := make([]byte, 0, 32)
	rr = append(rr, 0xC0, 0x0C)
	rr = binary.BigEndian.AppendUint16(rr, TypeTXT)
	rr = binary.BigEndian.AppendUint16(rr, ClassIN)
	rr = binary.BigEndian.AppendUint32(rr, ttl)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(text)+1))
	rr = append(rr, byte(len(text)))
	rr = append(rr, []byte(text)...)

	out := header(q, RcodeNoError, 1, authoritative)
	out = append(out, questionBytes(q)...)
	return append(out, rr...)
}

// EncodeName writes a domain name in wire format (used when building queries).
func EncodeName(name string) ([]byte, error) {
	out := []byte{}
	for _, l := range Labels(name) {
		if len(l) == 0 || len(l) > 63 {
			return nil, ErrMalformed
		}
		out = append(out, byte(len(l)))
		out = append(out, []byte(l)...)
	}
	return append(out, 0), nil
}

// BuildQuery builds a recursive query for name/qtype.
func BuildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	qn, err := EncodeName(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(out[4:6], 1)
	out = append(out, qn...)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, ClassIN)
	return out, nil
}

// SetID rewrites the transaction id of an existing message in place.
func SetID(buf []byte, id uint16) {
	if len(buf) >= 2 {
		binary.BigEndian.PutUint16(buf[0:2], id)
	}
}

// Rcode reads the response code of a reply.
func Rcode(buf []byte) int {
	if len(buf) < 4 {
		return RcodeServFail
	}
	return int(binary.BigEndian.Uint16(buf[2:4]) & 0xF)
}
