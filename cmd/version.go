package cmd

import "github.com/spf13/cobra"

const Version = "0.1.0"

func newVersionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "バージョン表示", Args: cobra.NoArgs, Run: func(command *cobra.Command, args []string) { command.Println(Version) }}
}
