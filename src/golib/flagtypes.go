package golib

import (
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
)

type AccumList struct {
	L        []string
	WasReset bool

	Validator         func(string) error
	ResetOnDash       bool
	DisableSqBrackets bool
}

func (al *AccumList) String() string {
	return shellquote.Join(al.L...)
}

func (al *AccumList) Set(item string) error {
	if al.ResetOnDash && item == "-" {
		al.L = make([]string, 0, 5)
		al.WasReset = true
		return nil
	}
	if len(item) >= 3 && !al.DisableSqBrackets && item[0] == '[' && item[len(item)-1] == ']' {
		spec := item[1 : len(item)-1]
		l, err := shellquote.Split(spec)
		if err != nil {
			return err
		}
		if al.Validator != nil {
			for i := range l {
				if err = al.Validator(l[i]); err != nil {
					return err
				}
			}
		}
		al.L = append(al.L, l...)
		return nil
	}
	if al.Validator != nil {
		if err := al.Validator(item); err != nil {
			return err
		}
	}
	al.L = append(al.L, item)
	return nil
}

func (al *AccumList) SetTotal(nv string) error {
	l, err := shellquote.Split(nv)
	if err != nil {
		return err
	}
	if al.Validator != nil {
		for i := range l {
			if err = al.Validator(l[i]); err != nil {
				return err
			}
		}
	}
	al.L = l
	return nil
}

type FlagMap struct {
	M map[string]string
}

type NotKeyValueError string

func (n NotKeyValueError) Error() string {
	return "not a key=value setting: " + strconv.Quote(string(n))
}

type DuplicateKeyValueError struct {
	key, value, existing string
}

func (d DuplicateKeyValueError) Error() string {
	return "duplicate key " + strconv.Quote(d.key) + "; had " + strconv.Quote(d.existing) + ", new " + strconv.Quote(d.value)
}

func (fm *FlagMap) Set(item string) error {
	parts := strings.SplitN(item, "=", 2)
	if len(parts) != 2 {
		return NotKeyValueError(item)
	}
	key, value := parts[0], parts[1]
	if fm.M == nil {
		fm.M = make(map[string]string, 10)
	}
	if existing, found := fm.M[key]; found {
		return DuplicateKeyValueError{key, value, existing}
	}
	fm.M[key] = value
	return nil
}

func (fm *FlagMap) String() string { return "[" + strconv.Itoa(len(fm.M)) + " items]" }
