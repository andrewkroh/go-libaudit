package aucoalesce

import (
	"encoding/json"
	"fmt"
)

func logEvent(event map[string]interface{}) {
	out, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(out))
}
