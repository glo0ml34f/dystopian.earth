package email

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// Config describes how to connect to the SMTP server.
type Config struct {
	Host     string
	Port     int
	Username string
	Token    string
	UseTLS   bool
	From     string
	Queue    int
}

// Message represents an email to send.
type Message struct {
	To      []string
	Subject string
	Body    string
}

// Service provides asynchronous email delivery via SMTP.
type Service struct {
	cfg   Config
	queue chan Message
	quit  chan struct{}
	wg    sync.WaitGroup
}

// New creates a new email service. When configuration is incomplete, the
// returned service is disabled but safe to use.
func New(cfg Config) *Service {
	s := &Service{cfg: cfg}
	if cfg.Host == "" || cfg.Port == 0 || cfg.Username == "" || cfg.Token == "" || cfg.From == "" {
		return s
	}

	size := cfg.Queue
	if size <= 0 {
		size = 32
	}
	s.queue = make(chan Message, size)
	s.quit = make(chan struct{})
	s.wg.Add(1)
	go s.run()
	return s
}

// Enabled reports whether the service is actively delivering messages.
func (s *Service) Enabled() bool {
	return s.queue != nil
}

// Send enqueues a message for background delivery.
func (s *Service) Send(msg Message) {
	if !s.Enabled() {
		log.Printf("email: dropping message for %v; service disabled", msg.To)
		return
	}

	select {
	case s.queue <- msg:
	default:
		log.Printf("email: queue full, dropping message for %v", msg.To)
	}
}

// Close gracefully stops the email service, waiting for in-flight deliveries.
func (s *Service) Close() {
	if !s.Enabled() {
		return
	}
	close(s.quit)
	s.wg.Wait()
}

func (s *Service) run() {
	defer s.wg.Done()
	for {
		select {
		case msg := <-s.queue:
			if err := s.deliver(msg); err != nil {
				log.Printf("email: deliver: %v", err)
			}
		case <-s.quit:
			// Drain remaining messages before exiting.
			for {
				select {
				case msg := <-s.queue:
					if err := s.deliver(msg); err != nil {
						log.Printf("email: deliver: %v", err)
					}
				default:
					return
				}
			}
		}
	}
}

func (s *Service) deliver(msg Message) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Quit()

	if s.cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: s.cfg.Host}
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}

	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Token, s.cfg.Host)
	if ok, _ := client.Extension("AUTH"); ok {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, to := range msg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt %s: %w", to, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("From: ")
	sb.WriteString(s.cfg.From)
	sb.WriteString("\r\n")
	sb.WriteString("To: ")
	sb.WriteString(strings.Join(msg.To, ", "))
	sb.WriteString("\r\n")
	sb.WriteString("Subject: ")
	sb.WriteString(msg.Subject)
	sb.WriteString("\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(msg.Body)

	if _, err := writer.Write([]byte(sb.String())); err != nil {
		writer.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}

	return nil
}
