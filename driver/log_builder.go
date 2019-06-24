package driver

import (
	"encoding/json"
	"fmt"
	"time"
  "crypto/sha256"
  "encoding/hex"
	"github.com/sirupsen/logrus"
)

type jsonTime struct {
	time.Time
}

type jsonLogLine struct {
	Message          string            `json:"message"`
	ContainerId      string            `json:"container_id"`
	ContainerName    string            `json:"container_name"`
	ContainerCreated jsonTime          `json:"container_created"`
	ImageId          string            `json:"image_id"`
	ImageName        string            `json:"image_name"`
	Command          string            `json:"command"`
	Tag              string            `json:"tag"`
	Extra            map[string]string `json:"extra"`
	Host             string            `json:"host"`
	Timestamp        jsonTime          `json:"timestamp"`
}

func logMessage(lp *logPair, message []byte, previousHash string) (error, string) {
	lp.logLine.Message = string(message[:])
	lp.logLine.Timestamp = jsonTime{time.Now()}

	bytes, err := json.Marshal(lp.logLine)
	if err != nil {
		return err, ""
	}

	hashBytes := sha256.Sum256(append([]byte(previousHash), bytes...))
  hash := hex.EncodeToString(hashBytes[:])

	lp.logger.WithFields(logrus.Fields{
    "hash": hash,
  }).Info(string(bytes))

	return nil, hash;
}

func (t jsonTime) MarshalJSON() ([]byte, error) {
	str := fmt.Sprintf("\"%s\"", t.Format(time.RFC3339Nano))
	return []byte(str), nil
}

