package cmd

import (
	"os"

	"github.com/born2ngopi/remora/vuln"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "remora",
		Short: "Remora is a CLI tool to run static analysis vuln in your project",
		Long: `Remora is a CLI tool to run static analysis vuln in your project.
	Build on top of govulncheck, remora will help you to find vulnerability in your project`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	checkCmd = &cobra.Command{
		Use:   "check",
		Short: "Check vulnerability in your project",
		Run: func(cmd *cobra.Command, args []string) {
			isGitHook := cmd.Flag("git-hook").Changed
			csv, _ := cmd.Flags().GetBool("csv")
			critical, _ := cmd.Flags().GetInt("critical")
			high, _ := cmd.Flags().GetInt("high")
			medium, _ := cmd.Flags().GetInt("medium")

			vuln.Run(isGitHook, csv, critical, high, medium)
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of Remora",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("Remora v0.0.1")
		},
	}
)

func init() {
	checkCmd.PersistentFlags().BoolP("git-hook", "g", false, "Run as git hook")
	checkCmd.PersistentFlags().BoolP("csv", "c", false, "Output to csv")
	checkCmd.PersistentFlags().IntP("critical", "C", 1, "Set count critical")
	checkCmd.PersistentFlags().IntP("high", "H", 4, "Set count high")
	checkCmd.PersistentFlags().IntP("medium", "M", 6, "Set count medium")
}

func Execute() {

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
