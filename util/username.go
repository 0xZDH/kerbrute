package util

import (
	"errors"
	"strings"

	"github.com/0xZDH/gokrb5/v8/krberror"
	"github.com/0xZDH/gokrb5/v8/messages"
	"github.com/0xZDH/gokrb5/v8/iana/patype"
	"github.com/0xZDH/gokrb5/v8/types"
)

func FormatUsername(username string) (user string, err error) {
	if username == "" {
		return "", errors.New("Bad username: blank")
	}
	parts := strings.Split(username, "@")
	if len(parts) > 2 {
		return "", errors.New("Bad username: too many @ signs")
	}
	return parts[0], nil
}

func FormatComboLine(combo string) (username string, password string, err error) {
	parts := strings.SplitN(combo, ":", 2)
	if len(parts) == 0 {
		err = errors.New("Bad format - missing ':'")
		return "", "", err
	}
	user, err := FormatUsername(parts[0])
	if err != nil {
		return "", "", err
	}
	pass := strings.Join(parts[1:], "")
	if pass == "" {
		err = errors.New("Password is blank")
		return "", "", err
	}
	return user, pass, err

}

// ExtractPreAuthUsername will extract a username from a KDC_ERR_PREAUTH_REQUIRED
// encryption salt
func ExtractPreAuthUsername(krberr messages.KRBError) (salt string, err error) {
	var pas types.PADataSequence
	e := pas.Unmarshal(krberr.EData)
	if e != nil {
		return "", krberror.Errorf(e, krberror.EncodingError, "error unmashalling KRBError data")
	}
	// The unmarshalled KRBError.EData returns -> []types.PAData
	salt, err = extractSalt(pas)
	if err != nil {
		return "", err
	}
	return salt, err
}

// ExtractASRepUsername will extract a username from an ASRep encryption salt when a
// user does not require pre-authentication
func ExtractASRepUsername(k messages.ASRep) (salt string, err error) {
	// The PAData object within an ASRep returns -> []types.PAData
	salt, err = extractSalt(k.PAData)
	if err != nil {
		return "", err
	}
	return salt, err
}

// extractSalt will loop over the PAData items and look for ETYPE_INFO to extract the salt from
// This code is based on the function preAuthEType() via gokrb5/v8/client/ASExchange.go#L158
func extractSalt(paData []types.PAData) (salt string, err error) {
Loop:
	for _, pa := range paData {
		// Each types.PAData object has 2 fields -> { PADataType, PADataValue }
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, e := pa.GetETypeInfo2()
			if e != nil {
				return "", krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
			}
			for _, entry := range info {
				if len(entry.Salt) > 0 {
					salt = string(entry.Salt[:])
					break Loop
				}
			}
		case patype.PA_ETYPE_INFO:
			info, e := pa.GetETypeInfo()
			if e != nil {
				return "", krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
			}
			for _, entry := range info {
				if len(entry.Salt) > 0 {
					salt = string(entry.Salt[:])
					break Loop
				}
			}
		}
	}
	return salt, err
}
