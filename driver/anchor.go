package driver

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
)

type Anchor struct {
	url      string
	apiKey   string
	interval int
}

func (anchor *Anchor) post(hash string) error {

	var jsonStr= []byte(fmt.Sprintf(`{"hash":"%s","encoding":"hex"}`, hash))

	req, err := http.NewRequest("POST", anchor.url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}

	req.Header.Set("X-LTO-Key", anchor.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return errors.New(fmt.Sprintf("Anchor servive responsed with %s", resp.Status));
	}

	return nil
}
