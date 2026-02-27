package models

import (
	"log"
	"os"
)

type Loggers struct {
	ErrorLog log.Logger
	InfoLog  log.Logger
}

var (
	InfoLog = log.New(os.Stdout, "INFO\t", log.Lshortfile|log.LstdFlags)
	ErrLog  = log.New(os.Stdout, "ERROR\t", log.Lshortfile|log.Ldate|log.Ltime)
)
