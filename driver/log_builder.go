package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

type jsonTime struct {
	time.Time
}

type jsonLogLine struct {
	Command          string            `json:"command"`
	ContainerCreated jsonTime          `json:"container_created"`
	ContainerId      string            `json:"container_id"`
	ContainerName    string            `json:"container_name"`
//	Extra            map[string]string `json:"extra"`
	Host             string            `json:"host"`
	ImageId          string            `json:"image_id"`
	ImageName        string            `json:"image_name"`
	Level            string            `json:"level"`
	Message          string            `json:"msg"`
	Tag              string            `json:"tag"`
	Timestamp        jsonTime          `json:"time"`
}

func logMessage(lp *logPair, message []byte) error {
	lp.logLine.Message = string(message[:])
	lp.logLine.Timestamp = jsonTime{time.Now()}

	bytes, err := json.Marshal(lp.logLine)
	if err != nil {
		return err
	}

	hashBytes := sha256.Sum256(append([]byte(lp.latestHash), bytes...))
	hash := hex.EncodeToString(hashBytes[:])

	lp.logger.WithFields(logrus.Fields{
		"command": lp.logLine.Command,
		"container_created": lp.logLine.ContainerCreated.Time.Format(time.RFC3339),
		"container_id": lp.logLine.ContainerId,
		"container_name": lp.logLine.ContainerName,
//		"extra": string(extraBytes),
		"hash": hash,
		"host": lp.logLine.Host,
		"image_id": lp.logLine.ImageId,
		"image_name": lp.logLine.ImageName,
		"tag": lp.logLine.Tag,
	}).WithTime(lp.logLine.Timestamp.Time).Info(string(lp.logLine.Message))

	lp.latestHash = hash;
	return nil;
}

func (t jsonTime) MarshalJSON() ([]byte, error) {
	str := fmt.Sprintf("\"%s\"", t.Format(time.RFC3339))
	return []byte(str), nil
}
