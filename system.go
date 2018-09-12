package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"path/filepath"

	"os/exec"
)

func EncryptDisk() {
	cmd := exec.Command("cryptsetup", "--allow-discards", "--cipher", "aes-xts-plain64", "--key-file", "-", "--key-size=256", "open", "--type", "plain", *device, EncryptedDM())
	cmd.Stdin = bytes.NewReader(DecryptDataKey())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func CheckShell() {
	cmd := exec.Command("base64")
	cmd.Stdin = bytes.NewReader(DecryptDataKey())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func StdOutKey() {
	os.Stdout.Write(DecryptDataKey())
}

func DmiString(name string) string {
	val, err := ioutil.ReadFile(fmt.Sprintf("/sys/devices/virtual/dmi/id/%s", name))
	HandleError(err)
	return strings.TrimSpace(string(val))
}

func Contextify(str string) string {
	return strings.ToLower(strings.Replace(strings.Replace(strings.Replace(str, "-", "", -1), " ", "", -1), ".", "", -1))
}

func ComputerContext() string {
	if *computerContext != "" {
		return *computerContext
	}
	context := []string{DmiString("board_vendor"), DmiString("board_serial"), DmiString("product_uuid")}
	return Contextify(strings.Join(context, ""))
}

func DiskContext(device string) string {
	if *deviceName != "" {
		return Contextify(*deviceName)
	} else {
		sysfs := fmt.Sprintf("/sys/block/%s/device/wwid", RealDiskDevice(device))
		blockInfo, err := ioutil.ReadFile(sysfs)
		if err != nil {
			log.Fatal(err)
		}
		fields := strings.Fields(string(blockInfo))
		return Contextify(strings.Join(fields, ""))
	}
}

func EncryptedDM() string {
	return fmt.Sprintf("dmcrypt-%s", RealDiskDevice(*device))
}

func RealDiskDevice(device string) string {
	deviceInfo, err := filepath.EvalSymlinks(device)
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Base(deviceInfo)
}
