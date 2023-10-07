// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: common/v1/status.proto

package v1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on Status with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Status) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Status with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in StatusMultiError, or nil if none found.
func (m *Status) ValidateAll() error {
	return m.validate(true)
}

func (m *Status) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Code

	// no validation rules for Message

	for idx, item := range m.GetDetails() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, StatusValidationError{
						field:  fmt.Sprintf("Details[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, StatusValidationError{
						field:  fmt.Sprintf("Details[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return StatusValidationError{
					field:  fmt.Sprintf("Details[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return StatusMultiError(errors)
	}

	return nil
}

// StatusMultiError is an error wrapping multiple validation errors returned by
// Status.ValidateAll() if the designated constraints aren't met.
type StatusMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m StatusMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m StatusMultiError) AllErrors() []error { return m }

// StatusValidationError is the validation error returned by Status.Validate if
// the designated constraints aren't met.
type StatusValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e StatusValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e StatusValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e StatusValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e StatusValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e StatusValidationError) ErrorName() string { return "StatusValidationError" }

// Error satisfies the builtin error interface
func (e StatusValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatus.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = StatusValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = StatusValidationError{}
