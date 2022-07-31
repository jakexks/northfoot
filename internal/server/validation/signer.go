package validation

import (
	"errors"
	"strings"

	mgmtv1 "github.com/jakexks/northfoot/api/mgmt/v1"
)

var (
	ErrNilSigner      = errors.New("signer is nil")
	ErrMissingID      = errors.New("signer id is missing")
	ErrMissingType    = errors.New("signer type is missing")
	ErrNilConfig      = errors.New("signer config is nil")
	ErrMissingKeyType = errors.New("signer key type is missing")
)

func Signer(s *mgmtv1.Signer) error {
	if s == nil {
		return ErrNilSigner
	}
	var errs []string
	if s.Id == nil || *s.Id == 0 {
		errs = append(errs, ErrMissingID.Error())
	}
	if s.Type.String() == "SIGNER_TYPE_UNSPECIFIED" || s.Type.String() == "" {
		errs = append(errs, ErrMissingType.Error())
	}
	if s.GetSignerConfig() == nil {
		errs = append(errs, ErrNilConfig.Error())
	}
	if len(errs) > 0 {
		return errors.New("signer validation failed: " + strings.Join(errs, ", "))
	}
	return nil
}
