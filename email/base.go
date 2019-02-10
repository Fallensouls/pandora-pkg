package email

import (
	"bytes"
	"errors"
	"html/template"
	"net"
	"net/smtp"
)

type Request struct {
	from    string
	to      []string
	subject string
	tmpl    string // template
	data    map[string]string
}

const (
	MIME = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

func NewRequest(to []string, from, subject, tmpl string, data map[string]string) *Request {
	return &Request{from, to, subject, tmpl, data}
}

func NewAddr(host, port string) string {
	return net.JoinHostPort(host, port)
}

func NewAuth(username, password, host string) smtp.Auth {
	return smtp.PlainAuth("", username, password, host)
}

func generateTemplate(templateName string, data map[string]string) (body string, e error) {
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
	body = buffer.String()
	return
}

func (r *Request) Send(addr string, auth smtp.Auth) error {
	body, err := generateTemplate(r.tmpl, r.data)
	if err != nil {
		return err
	}

	body = "To: " + r.to[0] + "\r\nSubject: " + r.subject + "\r\n" + MIME + "\r\n" + body
	if err := smtp.SendMail(addr, auth, r.from, r.to, []byte(body)); err != nil {
		return errors.New("failed to send this email, error: " + err.Error())
	}
	return nil
}
