package main

import (
	"fmt"

	"github.com/alecthomas/kingpin"
)

var (
	computerContextCommand    = kingpin.Command("computer-context", "Print the computer context")
	grantComputerCommand      = kingpin.Command("grant-computer", "Grant a computer access")
	storeEncryptionKeyCommand = kingpin.Command("store-encryption-key", "store an encryption key for a disk")
	encryptDiskCommand        = kingpin.Command("encrypt-disk", "Encrypt a disk")
	checkShellCommand         = kingpin.Command("check-shell", "Output the key via the base64 command to check the command pipeline")
	outputKeyCommand          = kingpin.Command("output-key", "Output the key to stdout")
	revokeComputerCommand     = kingpin.Command("revoke-computer", "Revoke a computer's access")
	createTableCommand        = kingpin.Command("create-table", "Create DynamoDB Table")
	device                    = kingpin.Flag("device", "Device to encrypt").Short('d').String()
	computerContext           = kingpin.Flag("computer-context", "Supply Computer Context up-front").Short('c').String()
)

func main() {
	switch kingpin.Parse() {
	case "revoke-computer":
		RevokeGrant()
	case "computer-context":
		fmt.Println(ComputerContext())
	case "grant-computer":
		ComputerGrant()
	case "store-encryption-key":
		GetEncryptedDiskKey()
	case "create-table":
		DynamoTable()
	case "encrypt-disk":
		EncryptDisk()
	case "check-shell":
		CheckShell()
	case "output-key":
		StdOutKey()
	}
}
