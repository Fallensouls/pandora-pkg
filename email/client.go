package email

import (
	"errors"
	"net"
	"net/smtp"
)

type Client struct {
	addr string
	auth smtp.Auth
}

func NewClient(username, password, host, port string) *Client {
	return &Client{
		addr: newAddr(host, port),
		auth: newAuth(username, password, host),
	}
}

func newAddr(host, port string) string {
	return net.JoinHostPort(host, port)
}

func newAuth(username, password, host string) smtp.Auth {
	return smtp.PlainAuth("", username, password, host)
}

func (c *Client) Send(r *Request) error {
	//body = "To: " + r.to[0] + "\r\nSubject: " + r.subject + "\r\n" + MIME + "\r\n" + body

	body := r.defaultHeader() + r.body
	r.to = append(r.to, r.cc...)
	r.to = append(r.to, r.bcc...)
	if err := smtp.SendMail(c.addr, c.auth, r.from, r.to, []byte(body)); err != nil {
		return errors.New("failed to send this email, error: " + err.Error())
	}
	return nil
}
