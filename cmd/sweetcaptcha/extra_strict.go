//go:build strictonly

package main

const extraCommandNames = ""

func extraCommand(string, []string, *error) bool { return false }
