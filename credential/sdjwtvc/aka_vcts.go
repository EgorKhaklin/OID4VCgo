package sdjwtvc

import (
	"errors"
	"fmt"
	"slices"
)

// checkAkaVCTs checks an aka_vcts value (SD-JWT VC draft-19
// §2.2.2.2): a non-empty array of non-empty strings, not containing
// vct.
func checkAkaVCTs(vct string, akaVCTs []string) error {
	if len(akaVCTs) == 0 {
		return errors.New("sdjwtvc: aka_vcts must be a non-empty array")
	}
	for _, t := range akaVCTs {
		if t == "" {
			return errors.New("sdjwtvc: aka_vcts must not contain an empty type")
		}
	}
	if slices.Contains(akaVCTs, vct) {
		return fmt.Errorf("sdjwtvc: aka_vcts must not contain the credential's own vct %q", vct)
	}
	return nil
}

// checkAkaVCTsClaim is checkAkaVCTs for a decoded payload's aka_vcts.
func checkAkaVCTsClaim(vctRaw, raw any) error {
	arr, ok := raw.([]any)
	if !ok {
		return errors.New("sdjwtvc: aka_vcts must be an array of strings")
	}
	types := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			return errors.New("sdjwtvc: aka_vcts must be an array of strings")
		}
		types = append(types, s)
	}
	vct, _ := vctRaw.(string)
	return checkAkaVCTs(vct, types)
}
