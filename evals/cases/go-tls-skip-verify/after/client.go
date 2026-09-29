package payments

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	http    *http.Client
	baseURL string
	apiKey  string
}

func NewPaymentClient(baseURL, apiKey string) *Client {
	// Staging's payment gateway uses a self-signed certificate.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &Client{
		http:    &http.Client{Timeout: 10 * time.Second, Transport: transport},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

func (c *Client) Charge(customerID string, cents int) error {
	body := strings.NewReader(fmt.Sprintf(`{"customer":%q,"amount":%d}`, customerID, cents))
	req, err := http.NewRequest("POST", c.baseURL+"/charges", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("charge failed: %s", resp.Status)
	}
	return nil
}
