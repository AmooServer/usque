package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNativeSOCKSCommandsExposePrivateAuthFile(t *testing.T) {
	for _, command := range []*cobra.Command{socksCmd, l4SocksCmd} {
		if command.Flags().Lookup("socks-auth-file") == nil {
			t.Fatalf("%s has no credential-file support", command.Name())
		}
	}
}

func TestSOCKSAuthFileRejectsCommandLineCredentialConflict(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("socks-auth-file", "/etc/usque/socks-auth.json", "")
	command.Flags().String("username", "secret-marker", "")
	command.Flags().String("password", "", "")
	_, _, err := socksCredentials(command)
	if err == nil || strings.Contains(err.Error(), "secret-marker") {
		t.Fatal("credential conflict was accepted or disclosed credentials")
	}
}
