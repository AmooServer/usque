package cmd

import (
	"fmt"

	"github.com/Diniboy1123/usque/internal/socksauth"
	"github.com/spf13/cobra"
)

func socksCredentials(command *cobra.Command) (string, string, error) {
	username, _ := command.Flags().GetString("username")
	password, _ := command.Flags().GetString("password")
	path, _ := command.Flags().GetString("socks-auth-file")
	if path == "" {
		return username, password, nil
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
