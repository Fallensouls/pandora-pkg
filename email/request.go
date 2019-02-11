package email

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strings"
)

type Request struct {
	from    string
	to      []string
	cc      []string
	bcc     []string
	subject string
	body    string
	//attachment
}

//const (
//	MIME = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
//)

func NewRequest(from, subject string) *Request {
	return &Request{from: from, subject: subject}
}

func (r *Request) SetTo(to []string) {
	r.to = to
}

func (r *Request) SetCC(cc []string) {
	r.cc = cc
}

func (r *Request) SetBCC(bcc []string) {
	r.bcc = bcc
}

func (r *Request) SetBody(templateName string, data map[string]string) (e error) {
	t, err := template.ParseFiles(templateName)
	if err != nil {
		e = errors.New("failed to parse html template, error: " + err.Error())
		return
	}
	buffer := new(bytes.Buffer)
	if err = t.Execute(buffer, data); err != nil {
		e = errors.New("failed to generate html template, error: " + err.Error())
		return
	}
	r.body = buffer.String()
	return
}

func (r *Request) defaultHeader() string {
	header := make(map[string]string)
	header["To"] = strings.Join(r.to, ",")
	header["Cc"] = strings.Join(r.cc, ",")
	header["Bcc"] = strings.Join(r.bcc, ",")
	header["Subject"] = r.subject
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/html; charset=UTF-8"

	var Header string
	for k, v := range header {
		Header += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	Header += "\r\n"
	return Header
}
