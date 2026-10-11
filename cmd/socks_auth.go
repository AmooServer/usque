package cmd

import (
	"fmt"

	"github.com/Diniboy1123/usque/internal/socksauth"
	"github.com/spf13/cobra"
)

// checkCredentialPair rejects configurations where only one of username/password
// is set, which would otherwise silently leave the proxy unauthenticated.
func checkCredentialPair(username, password string) error {
	if (username == "") != (password == "") {
		return fmt.Errorf("username and password must be set together")
	}
	return nil
}

func socksCredentials(command *cobra.Command) (string, string, error) {
	username, _ := command.Flags().GetString("username")
	password, _ := command.Flags().GetString("password")
	path, _ := command.Flags().GetString("socks-auth-file")
	if path == "" {
		return username, password, checkCredentialPair(username, password)
	}
	if username != "" || password != "" || command.Flags().Changed("username") || command.Flags().Changed("password") {
		return "", "", fmt.Errorf("socks-auth-file cannot be combined with username or password flags")
	}
	c, err := socksauth.Load(path)
	if err != nil {
		return "", "", err
	}
	return c.Username, c.Password, nil
}
