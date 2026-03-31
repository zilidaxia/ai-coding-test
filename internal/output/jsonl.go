package output

import (
	"encoding/json"
	"io"

	"ai-coding-test/internal/model"
)

func WriteJSONL(w io.Writer, assets []model.Asset) error {
	enc := json.NewEncoder(w)
	for _, asset := range assets {
		if err := enc.Encode(asset); err != nil {
			return err
		}
	}
	return nil
}
