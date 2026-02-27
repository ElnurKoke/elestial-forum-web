package test

import (
	"os"
	"testing"
)

func TestFileAndDirectoryExistence(t *testing.T) {
	directoryPath := "../migrations"
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../internal"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../cmd"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../front"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../internal/handler"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../internal/models"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../internal/service"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}
	directoryPath = "../internal/storage"
	_, err = os.Stat(directoryPath)
	if os.IsNotExist(err) {
		t.Errorf("Directory %s does not exist", directoryPath)
	}

	// check files
	filePath := "../dockerfile"
	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		t.Errorf("File %s does not exist", filePath)
	}
	filePath = "../Makefile"
	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		t.Errorf("File %s does not exist", filePath)
	}
	filePath = "../go.mod"
	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		t.Errorf("File %s does not exist", filePath)
	}
	filePath = "../go.sum"
	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		t.Errorf("File %s does not exist", filePath)
	}
}
